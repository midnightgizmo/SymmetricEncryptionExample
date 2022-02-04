// See https://aka.ms/new-console-template for more information
using Encryption_DotNet6.Security;
using System.Text;

string DataToEncrypt = "this is some data to encrypt";
string passwordToEncryptData = "Some password";

string encryptedData = Encryption.Encrypt(DataToEncrypt, passwordToEncryptData, EncryptionType.Enc128);
Console.WriteLine("The following line will be encrypted");
Console.WriteLine(DataToEncrypt);
Console.WriteLine("Encrypted Data");
Console.WriteLine(encryptedData);

Console.WriteLine();


Console.WriteLine("now lets decrypt the data");
string DecryptedData = Encryption.Decrypt(encryptedData, passwordToEncryptData, EncryptionType.Enc128);
Console.WriteLine(DecryptedData);

