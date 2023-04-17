using System.Security.Cryptography;
using System.Text;

namespace HashPayloadConsoleApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string payload = "Hello, world!"; // Your arbitrary payload
            ECParameters publicKeyParameters;
            byte[] payloadBytes;
            string base64SignatureBytes;

            Console.WriteLine($"Original Payload: {payload}");

            // Generate a new RSA key pair
            using (var rsa = ECDsa.Create(ECCurve.NamedCurves.brainpoolP160r1))
            {
                // Get the public and private key as byte arrays
                publicKeyParameters = rsa.ExportParameters(false);

                // Convert the payload to a byte array
                payloadBytes = Encoding.UTF8.GetBytes(payload);

                // Compute the hash of the payload using SHA256
                byte[] hashBytes = GetPayloadHash(payloadBytes);

                // Sign the hash using the private key
                byte[] signatureBytes = rsa.SignHash(hashBytes);
                                
                base64SignatureBytes = Convert.ToBase64String(signatureBytes);
                Console.WriteLine(base64SignatureBytes);
            }

            // change payload
            payloadBytes = TryHackPayload(payloadBytes);

            // verify the payload -> check the signature (integrity, authentication)
            VerifyHash(payloadBytes, base64SignatureBytes, publicKeyParameters);
        }

        private static byte[] TryHackPayload(byte[] payloadBytes)
        {
            var payload = Encoding.UTF8.GetString(payloadBytes);
            var newPayload = payload.Replace('o', 'u');
            return Encoding.UTF8.GetBytes(newPayload);
        }

        private static byte[] GetPayloadHash(byte[] payloadBytes)
        {
            return MD5.HashData(payloadBytes);
        }

        private static void VerifyHash(byte[] payloadBytes, string base64SignatureBytes, ECParameters parameters)
        {
            using (var rsa = ECDsa.Create(parameters))
            {
                // Compute the hash of the payload using SHA256
                byte[] hashBytes = GetPayloadHash(payloadBytes);

                // verify the signature using the public key
                var signatureBytes = Convert.FromBase64String(base64SignatureBytes);
                bool signaturevalid = rsa.VerifyHash(hashBytes, signatureBytes);

                Console.WriteLine("signature is valid: {0}", signaturevalid);

                var payload = Encoding.UTF8.GetString(payloadBytes);
                Console.WriteLine($"Received Payload: {payload}");
                Console.Read();
            }
        }
    }
}