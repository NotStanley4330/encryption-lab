using System.Security.Cryptography;
using System.Text;
using System.Collections;
using System.Text.Json;
using Microsoft.Extensions.Logging;

internal sealed class EncryptedEchoServer : EchoServerBase {

    RSA rsa;
    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoServer> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoServer>()!;

    /// <inheritdoc />
    internal EncryptedEchoServer(ushort port) : base(port) 
    { 
        rsa = RSA.Create(2048); //creates an RSA public key of 2048 bits
    }

    // todo: Step 1: Generate a RSA key (2048 bits) for the server.
           
    /// <inheritdoc />
    public override string GetServerHello() {
        //Step 1: Send the public key to the client in PKCS#1 format.
        byte[] publicKey = rsa.ExportRSAPublicKey();
        // Encode using Base64: Convert.ToBase64String
        return Convert.ToBase64String(publicKey);
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input) {
        //Step 1: Deserialize the message.
        var message = JsonSerializer.Deserialize<EncryptedMessage>(input);
        
        //Step 2: Decrypt the message using hybrid encryption.
        //first we will decrypt the keys
        byte[] aesKey = rsa.Decrypt(message.AesKeyWrap, RSAEncryptionPadding.OaepSHA256);
        byte[] hmacKey = rsa.Decrypt(message.HMACKeyWrap, RSAEncryptionPadding.OaepSHA256);
        
        //Do the aes decryption next
        Aes aes = Aes.Create();
        aes.Key = aesKey;
        aes.IV = message.AESIV;
        byte[] decryptedMessage = aes.DecryptCbc(message.Message, message.AESIV, PaddingMode.PKCS7);
        string messageText = Encoding.UTF8.GetString(decryptedMessage);
        

        // Step 3: Verify the HMAC.
        // Throw an InvalidSignatureException if the received hmac is bad
        HMACSHA256 hmac = new HMACSHA256(hmacKey);
        byte[] computedHash = hmac.ComputeHash(decryptedMessage);
        if (!computedHash.SequenceEqual(message.HMAC))
        {
            throw new InvalidSignatureException("Recieved HMAC is bad!");
        }

        //Step 3: Return the decrypted and verified message from the server.
        return Settings.Encoding.GetString(decryptedMessage);
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input) {
        byte[] data = Settings.Encoding.GetBytes(input);

        //Step 1: Sign the message.
        // Use PSS padding with SHA256.
        byte[] messageSignature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        //Step 2: Put the data in an SignedMessage object and serialize to JSON.
        // Return that JSON.
        var message = new SignedMessage(data, messageSignature);
        return JsonSerializer.Serialize(message);
    }
}