using System.Security.Cryptography;
using System.Text;

namespace HashPayloadConsoleApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string payload = """
                Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod 
                tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. 
                At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, 
                no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, 
                consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore 
                magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo 
                dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.
                """;
            ECParameters publicKeyParameters;
            byte[] payloadBytes;
            string base64SignatureBytes;

            Console.WriteLine($"Original Payload:");
            Console.WriteLine();
            Console.WriteLine($"{payload}");

            // Generate a new key pair
            using (ECDsa asymmetricAlgorithm = ECDsa.Create(ECCurve.NamedCurves.brainpoolP160r1))
            {
                // Get the public key
                publicKeyParameters = asymmetricAlgorithm.ExportParameters(false);

                // Convert the payload to a byte array
                payloadBytes = Encoding.UTF8.GetBytes(payload);

                // Compute the hash of the payload
                byte[] hashBytes = GetPayloadHash(payloadBytes);

                // Sign the hash using the private key
                byte[] signatureBytes = asymmetricAlgorithm.SignHash(hashBytes);

                base64SignatureBytes = Convert.ToBase64String(signatureBytes);
                Console.WriteLine();
                Console.WriteLine($"{base64SignatureBytes}    lenght: {base64SignatureBytes.Length}");
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
            byte[] hashBytes;
            using (SHA256 sha256 = SHA256.Create())
            {
                hashBytes = sha256.ComputeHash(payloadBytes);
            }

            return hashBytes;
        }

        private static void VerifyHash(byte[] payloadBytes, string base64SignatureBytes, ECParameters parameters)
        {
            using (var rsa = ECDsa.Create(parameters))
            {
                // Compute the hash of the payload
                byte[] hashBytes = GetPayloadHash(payloadBytes);

                // verify the signature using the public key
                var signatureBytes = Convert.FromBase64String(base64SignatureBytes);
                bool signaturevalid = rsa.VerifyHash(hashBytes, signatureBytes);

                Console.WriteLine("signature is valid: {0}", signaturevalid);
                Console.WriteLine();

                var payload = Encoding.UTF8.GetString(payloadBytes);
                Console.WriteLine($"Received Payload:");
                Console.WriteLine();
                Console.WriteLine($"{payload}");
                Console.Read();
            }
        }
    }
}
