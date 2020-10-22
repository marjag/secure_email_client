namespace mailer.Models
{
    public interface ICipherDriver
    {
        // encrypts message
        string Encrypt(string text);
        //decrypts message
        string Decrypt(string ciphertext);
    }
}