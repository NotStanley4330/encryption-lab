using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using System.IO;
using Microsoft.Extensions.Logging;

/// <summary>
/// Provides a base class for implementing an Echo client.
/// </summary>
internal sealed class EncryptedEchoClient : EchoClientBase {

    RSA rsa;
    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoClient> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoClient>()!;

    /// <inheritdoc />
    public EncryptedEchoClient(ushort port, string address) : base(port, address) 
    { 
        rsa = RSA.Create();
    }

    /// <inheritdoc />
    public override void ProcessServerHello(string message) 
    {
        //Step 1: Get the server's public key. Decode using Base64.
        // Throw a CryptographicException if the received key is invalid.
        byte[] publicKeyBytes = Convert.FromBase64String(message);
        rsa.ImportRSAPublicKey(publicKeyBytes, out _);
        Logger.LogInformation("Public key loaded from server hello");
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input) 
    {

        //Step 1: Encrypt the input using hybrid encryption.
        // Encrypt using AES with CBC mode and PKCS7 padding.
        // Use a different key each time.
        Aes aes = Aes.Create();
        aes.GenerateIV();
        aes.GenerateKey();
        byte[] plainBytes = Encoding.UTF8.GetBytes(input);
        byte[] encryptedInput = aes.EncryptCbc(plainBytes, aes.IV, PaddingMode.PKCS7);

        //Step 2: Generate an HMAC of the message.
        // Use the SHA256 variant of HMAC.
        // Use a different key each time.
        HMACSHA256 hmac = new HMACSHA256();
        byte[] hash = hmac.ComputeHash(plainBytes);

        //Step 3: Encrypt the message encryption and HMAC keys using RSA.
        // Encrypt using the OAEP padding scheme with SHA256.
        byte[] aesKeyEncrypted = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
        byte[] hmacKeyEncrypted = rsa.Encrypt(hmac.Key, RSAEncryptionPadding.OaepSHA256);


        // todo: Step 4: Put the data in an EncryptedMessage object and serialize to JSON.
        // Return that JSON.
        var message = new EncryptedMessage(aesKeyEncrypted, aes.IV, encryptedInput, hmacKeyEncrypted, hash);
        return JsonSerializer.Serialize(message);
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input) {
        //Step 1: Deserialize the message.
        var signedMessage = JsonSerializer.Deserialize<SignedMessage>(input);

        //Step 2: Check the messages signature.
        // Use PSS padding with SHA256.
        // Throw an InvalidSignatureException if the signature is bad.
        bool isValid = rsa.VerifyData(signedMessage.Message, signedMessage.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        if (!isValid)
        {
            throw new InvalidSignatureException("Signature was invalid!");
        }

        //Step 3: Return the message from the server.
        return Settings.Encoding.GetString(signedMessage.Message);
    }
}