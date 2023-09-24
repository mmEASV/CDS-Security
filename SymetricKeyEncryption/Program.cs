using System.Security.Cryptography;
using System.Text;

Console.Write("Passphrase: ");
string passphrase = Console.ReadLine();   

while(true)
{
    Console.WriteLine("");   
    Console.WriteLine("1: Safely store message");   
    Console.WriteLine("2: Read message");
    Console.WriteLine("0: Exit");
    Console.Write("> "); 

    int userInput = Convert.ToInt32(Console.ReadLine());
    switch (userInput)
    {
        case 1:
            Console.Write("Type a message to encrypt: ");
            string message = Console.ReadLine();
            string encryptedMessage = Encrypt(message, passphrase);
            File.WriteAllText("message.txt", encryptedMessage);
            break;
        case 2:
            string encrypted = File.ReadAllText("message.txt");
            string decryptedMessage = Decrypt(encrypted, passphrase);
            Console.WriteLine(decryptedMessage);
            break;
        case 0:
            return;
        default:
            Console.WriteLine("Invalid option. Please select a valid one.");
            break;
    }
}



static string Encrypt(string text, string passphrase)
{
    using AesGcm aesGcm = new AesGcm(Encoding.UTF8.GetBytes(passphrase));
    byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
    byte[] cipherText = new byte[Encoding.UTF8.GetByteCount(text)];
    byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];

    aesGcm.Encrypt(nonce, 
                   Encoding.UTF8.GetBytes(text), 
                   cipherText,
                   tag);

    return $"{Convert.ToBase64String(nonce)}.{Convert.ToBase64String(cipherText)}.{Convert.ToBase64String(tag)}";
}

static string Decrypt(string cipherTextTagNonce, string passphrase)
{
    string[] parts = cipherTextTagNonce.Split('.');
    byte[] nonce = Convert.FromBase64String(parts[0]);
    byte[] cipherText = Convert.FromBase64String(parts[1]);
    byte[] tag = Convert.FromBase64String(parts[2]);

    byte[] decryptedData = new byte[cipherText.Length];

    using AesGcm aesGcm = new AesGcm(Encoding.UTF8.GetBytes(passphrase));
    aesGcm.Decrypt(nonce, 
                   cipherText, 
                   tag, 
                   decryptedData);

    return Encoding.UTF8.GetString(decryptedData);
}