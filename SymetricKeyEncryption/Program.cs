using System.Security.Cryptography;
using System.Text;

Console.WriteLine();
Console.WriteLine("********************************");
Console.WriteLine("**** Symetric Key Encryption ****");
Console.WriteLine("********************************");
Console.WriteLine();

Console.Write("Enter passphrase: ");
string? passphrase = Console.ReadLine();
var salt = new byte[16];
RandomNumberGenerator.Fill(salt);
using var pbkdf2 = new Rfc2898DeriveBytes(passphrase ?? "Passphrase", salt, 600000, HashAlgorithmName.SHA256);

var key = pbkdf2.GetBytes(32);

while (true) 
{
    Console.WriteLine();
    Console.WriteLine("Choose an option:");
    Console.WriteLine("1: Safely store message");
    Console.WriteLine("2: Read message");
    Console.WriteLine("0: Exit");
    Console.Write("> ");
    string? userInput = Console.ReadLine();
    
    if (!int.TryParse(userInput, out int result)) 
    {
        Console.WriteLine("Invalid input, please enter a number!");
        continue;
    }

    switch (result)
    {
        case 1:
            Console.WriteLine();
            Console.Write("Enter a message to encrypt: ");
            string message = Console.ReadLine() ?? "";
            string encryptedMessage = Encrypt(message, key);
            File.WriteAllText("message.txt", encryptedMessage);
            Console.WriteLine("Message successfully encrypted and stored.");
            break;
        case 2:
            if (!File.Exists("message.txt"))
            {
                Console.WriteLine("No encrypted message found. Please store a message first.");
                break;
            }
            string encrypted = File.ReadAllText("message.txt");
            string decryptedMessage = Decrypt(encrypted, key);
            Console.WriteLine(decryptedMessage);
            break;
        case 0:
            return;
        default:
            Console.WriteLine("Invalid option. Please select a valid one.");
            break;
    }
}

static string Encrypt(string text, byte[] key)
{
    using AesGcm aesGcm = new AesGcm(key);
    byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
    byte[] cipherText = new byte[Encoding.UTF8.GetByteCount(text)];
    byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];

    aesGcm.Encrypt(nonce, 
                   Encoding.UTF8.GetBytes(text), 
                   cipherText, 
                   tag);

    return $"{Convert.ToBase64String(nonce)}.{Convert.ToBase64String(cipherText)}.{Convert.ToBase64String(tag)}";
}

static string Decrypt(string cipherTextTagNonce, byte[] key)
{
    string[] parts = cipherTextTagNonce.Split('.');
    byte[] nonce = Convert.FromBase64String(parts[0]);
    byte[] cipherText = Convert.FromBase64String(parts[1]);
    byte[] tag = Convert.FromBase64String(parts[2]);

    byte[] decryptedData = new byte[cipherText.Length];

    using AesGcm aesGcm = new AesGcm(key);
    aesGcm.Decrypt(nonce, 
                   cipherText, 
                   tag, 
                   decryptedData);

    return Encoding.UTF8.GetString(decryptedData);
}