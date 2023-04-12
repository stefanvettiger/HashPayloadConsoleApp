using System.Security.Cryptography;
using System.Text;

namespace HashPayloadConsoleApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string payload = "Hello, world!"; // Your arbitrary payload
            RSAParameters publicKeyParameters;
            byte[] payloadBytes;
            byte[] signatureBytes;

            Console.WriteLine($"Original Payload: {payload}");

            // Generate a new RSA key pair
            using (RSA rsa = RSA.Create())
            {
                // Get the public and private key as byte arrays
                publicKeyParameters = rsa.ExportParameters(false);

                // Convert the payload to a byte array
                payloadBytes = Encoding.UTF8.GetBytes(payload);

                // Compute the hash of the payload using SHA256
                byte[] hashBytes = GetPayloadHash(payloadBytes);

                // Sign the hash using the private key
                signatureBytes = rsa.SignHash(hashBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }

            // change payload
            payloadBytes = TryHackPayload(payloadBytes);

            // verify the payload -> check the signature (integrity, authentication)
            VerifyHash(payloadBytes, signatureBytes, publicKeyParameters);
        }

        private static byte[] TryHackPayload(byte[] payloadBytes)
        {
            var payload = Encoding.UTF8.GetString(payloadBytes);
            var newPayload = payload.Replace('o', 'u');
            return Encoding.UTF8.GetBytes(newPayload);
        }

        private static byte[] GetPayloadHash(byte[] payloadBytes)
        {
            byte[] hashBytes;
            using (SHA256 sha256 = SHA256.Create())
            {
                hashBytes = sha256.ComputeHash(payloadBytes);
            }

            return hashBytes;
        }

        private static void VerifyHash(byte[] payloadBytes, byte[] signatureBytes, RSAParameters parameters)
        {
            using (RSA rsa = RSA.Create(parameters))
            {
                // Compute the hash of the payload using SHA256
                byte[] hashBytes = GetPayloadHash(payloadBytes);

                // verify the signature using the public key
                bool signaturevalid = rsa.VerifyHash(hashBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                Console.WriteLine("signature is valid: {0}", signaturevalid);
                
                var payload = Encoding.UTF8.GetString(payloadBytes);
                Console.WriteLine($"Received Payload: {payload}");
                Console.Read();
            }
        }
    }
}