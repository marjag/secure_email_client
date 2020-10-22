using System.Text;
using System;

namespace mailer.Models
{
    public class Rc4 : ICipherDriver
    {
        // holds key
        private string key;
        public string Key
        {
            get => key;
            set => key = value;
        }
        public Rc4(string key = "abcdefghijklmnoprstu") {
            this.key = key;
        }

        public string Encrypt(string plaintextMessage)
        {
            string ciphertext = "";
            ciphertext = RC4(plaintextMessage, this.key);
            string ciphertextHex = ToHexString(ciphertext);
            return ciphertextHex.Trim();
        }

        public string Decrypt(string ciphertextHex)
        {
            string ciphertext = "";
            string plaintextMessage = "";
            ciphertextHex = ciphertextHex.Trim();
            ciphertext = FromHexString(ciphertextHex);
            plaintextMessage = RC4(ciphertext, this.key);
            return plaintextMessage;
        }


        // stream rc4
        private string RC4(string input, string key)
        {
            StringBuilder result = new StringBuilder();
            int x, y, j = 0;
            int[] box = new int[256];
            for (int i = 0; i < 256; i++)
                box[i] = i;
            for (int i = 0; i < 256; i++)
            {
                j = (key[i % key.Length] + box[i] + j) % 256;
                x = box[i];
                box[i] = box[j];
                box[j] = x;
            }
            for (int i = 0; i < input.Length; i++)
            {
                y = i % 256;
                j = (box[y] + j) % 256;
                x = box[y];
                box[y] = box[j];
                box[j] = x;
                result.Append((char)(input[i] ^ box[(box[y] + box[j]) % 256]));
            }
            return result.ToString();
        }

        public static string ToHexString(string str)
        {
            var sb = new StringBuilder();

            var bytes = Encoding.Unicode.GetBytes(str);
            foreach (var t in bytes)
            {
                sb.Append(t.ToString("X2"));
            }

            return sb.ToString();
        }

        public static string FromHexString(string hexString)
        {
            var bytes = new byte[hexString.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            return Encoding.Unicode.GetString(bytes);
        }

    }

}
