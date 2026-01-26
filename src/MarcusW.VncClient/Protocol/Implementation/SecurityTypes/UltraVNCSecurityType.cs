using MarcusW.VncClient.Protocol.SecurityTypes;
using MarcusW.VncClient.Security;
using MarcusW.VncClient.Utils;
using Org.BouncyCastle.Security;
using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Linq;
//using System.Numerics;
//using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using System.Runtime.Intrinsics.Wasm;

namespace MarcusW.VncClient.Protocol.Implementation.SecurityTypes
{
    /// <summary>
    /// A security type that implements UltraVNC authentication with enhanced security features.
    /// This provides improved password hashing and additional security mechanisms over standard VNC.
    /// </summary>
    public class UltraVNCSecurityType : ISecurityType
    {
        private readonly RfbConnectionContext _context;

        /// <summary>
        /// Specifies the max password length for UltraVNC enhanced authentication.
        /// </summary>
        private const int PASSLENGTH = 64;
        /// <summary>
        /// Specifies the max (domain and) username length for UltraVNC enhanced authentication.
        /// </summary>
        private const int USERLENGTH = 256;


        /// <inheritdoc />
        public byte Id => (byte)WellKnownSecurityType.UltraVNC;

        /// <inheritdoc />
        public string Name => "UltraVNC";

        /// <inheritdoc />
        public int Priority =>30; // Higher than basic VNC auth due to enhanced security

        /// <summary>
        /// Initializes a new instance of the <see cref="UltraVNCSecurityType"/>.
        /// </summary>
        /// <param name="context">The connection context.</param>
        public UltraVNCSecurityType(RfbConnectionContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        /// <inheritdoc />
        public async Task<AuthenticationResult> AuthenticateAsync(IAuthenticationHandler authenticationHandler, CancellationToken cancellationToken = default)
        {
            if (authenticationHandler == null)
                throw new ArgumentNullException(nameof(authenticationHandler));

            cancellationToken.ThrowIfCancellationRequested();

            ITransport transport = _context.Transport ?? throw new InvalidOperationException("Cannot access transport for authentication.");

            // Read & resend authentication mode to start challenge-response.
            var authModeBytes = new byte[6];
            await transport.Stream.ReadExactlyAsync(authModeBytes, cancellationToken).ConfigureAwait(false);
            var authMode = new byte[1] { authModeBytes[5] }; //2 = Ultra mode with 2 passwords (normal & viewonly), 113 = MSLogonII mode
            await transport.Stream.WriteAsync(authMode, cancellationToken).ConfigureAwait(false);

            //Standard UltraVNC authentication
            if (authMode[0] == 2)
            {
                // Read challenge from server (16 bytes)
                byte[] challengeBuffer = new byte[16];
                await transport.Stream.ReadExactlyAsync(challengeBuffer, cancellationToken).ConfigureAwait(false);

                // Request password input
                PasswordAuthenticationInput input = await authenticationHandler
                    .ProvideAuthenticationInputAsync(_context.Connection, this, new PasswordAuthenticationInputRequest()).ConfigureAwait(false);

                // Calculate response
                byte[] response = CreateUltraResponse(challengeBuffer, input.Password);

                // Send response
                await transport.Stream.WriteAsync(response, cancellationToken).ConfigureAwait(false);

                return new AuthenticationResult();
            }
            // MS Logon II UltraVNC authentication
            else if (authMode[0] == 113)
            {
                // Read DH params (8-byte big-endian each)
                //var genBytes = (await transport.Stream.ReadAllAsync(8, cancellationToken)).ToArray();
                //var modBytes = (await transport.Stream.ReadAllAsync(8, cancellationToken)).ToArray();
                //var pubBytes = (await transport.Stream.ReadAllAsync(8, cancellationToken)).ToArray();

                byte[] generatorBytes = new byte[8];
                byte[] modulusBytes = new byte[8];
                byte[] publicBytes = new byte[8];

                await transport.Stream.ReadExactlyAsync(generatorBytes, cancellationToken).ConfigureAwait(false);
                await transport.Stream.ReadExactlyAsync(modulusBytes, cancellationToken).ConfigureAwait(false);
                await transport.Stream.ReadExactlyAsync(publicBytes, cancellationToken).ConfigureAwait(false);


                // Build BigIntegers as unsigned big-endian
                //var generatorInt = new BigInteger(genBytes, isUnsigned: true, isBigEndian: true);
                //var modulusInt = new BigInteger(modBytes, isUnsigned: true, isBigEndian: true);
                //var pubvalInt = new BigInteger(pubBytes, isUnsigned: true, isBigEndian: true);
                var generatorInt = new BigInteger(1, generatorBytes, true);
                var modulusInt = new BigInteger(1,modulusBytes,true);
                var publicInt = new BigInteger(1,publicBytes,true);

                Debug.WriteLine($"g={generatorInt}, m={modulusInt}, p={modulusInt}");

                // Generate PrivateX
                byte[] clientRandomBytes = new byte[8];
                //using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(xBytes);

                var randomGenerator = new SecureRandom();
                randomGenerator.NextBytes(clientRandomBytes);

                //var privateX = new BigInteger(clientRandomBytes, isUnsigned: true, isBigEndian: true);
                //if (privateX.IsZero) privateX = BigInteger.One;
                //privateX %= (modulusInt - BigInteger.One);
                //if (privateX.IsZero) privateX = BigInteger.One;
                //Debug.WriteLine($"X={privateX}");

                var privateX = new BigInteger(1, clientRandomBytes, true);
                if (privateX.Equals(BigInteger.Zero)) privateX = BigInteger.One;
                privateX = privateX.Mod(modulusInt.Subtract(BigInteger.One));
                if (privateX.Equals(BigInteger.Zero)) privateX = BigInteger.One;
                Debug.WriteLine($"X={privateX}");


                // Compute client public B = g^x mod p
                //var publicB = BigInteger.ModPow(generatorInt, privateX, modulusInt);
                //Debug.WriteLine($"B={publicB}");
                var publicB = generatorInt.ModPow(privateX, modulusInt);
                Debug.WriteLine($"B={publicB}");

                // Send publicB as 8-byte big-endian
                byte[] publicBBytes = BigIntegers.AsUnsignedByteArray(8, publicB);
                //WriteBigEndianU64(publicB, publicBBytes);
                await transport.Stream.WriteAsync(publicBBytes, cancellationToken).ConfigureAwait(false);

                // Compute shared secret S = A^x mod p
                //var sharedSecret = BigInteger.ModPow(publicInt, privateX, modulusInt);
                //Debug.WriteLine($"Secret={sharedSecret}");
                var sharedSecret = publicInt.ModPow(privateX, modulusInt);
                Debug.WriteLine($"Secret={sharedSecret}");

                // Export secret as 8-byte big-endian
                byte[] sharedSecretByte = BigIntegers.AsUnsignedByteArray(8, sharedSecret);

                CredentialsAuthenticationInput input = await authenticationHandler
                    .ProvideAuthenticationInputAsync(_context.Connection, this, new CredentialsAuthenticationInputRequest()).ConfigureAwait(false);

                byte[] response = CreateEnhancedUltraResponse(sharedSecretByte, input.Username, input.Password);

                await transport.Stream.WriteAsync(response, cancellationToken).ConfigureAwait(false);

                return new AuthenticationResult();
            }
            else
            {
                throw new NotSupportedException($"Ultra authentication mode {authMode[0]} is not supported by {this.Name}.");
            }

        }

        /// <inheritdoc />
        public Task ReadServerInitExtensionAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        /// <summary>
        /// Creates an Ultra-style authentication response with enhanced security.
        /// </summary>
        /// <param name="challenge">The challenge from the server.</param>
        /// <param name="password">The password.</param>
        /// <returns>The authentication response.</returns>
        private static byte[] CreateUltraResponse(byte[] challenge, string password)
        {
            var key = new byte[8];
            byte[] pwdBytes = Encoding.ASCII.GetBytes(password ?? string.Empty);
            Array.Copy(pwdBytes, key, Math.Min(8, pwdBytes.Length));

            key = ReverseBitOrder(key);

            //// Encrypt challenge
            //using var desProvider = DES.Create();
            //desProvider.Key = key;
            //desProvider.Mode = CipherMode.ECB;
            //desProvider.Padding = PaddingMode.None;
            //using var encryptor = desProvider.CreateEncryptor();

            //// Encrypt challenge with key
            //var response = new byte[16];
            //encryptor.TransformBlock(challenge.ToArray(), 0, challenge.Length, response, 0);

            var engine = new DesEngine();
            var keyParam = new KeyParameter(key);
            engine.Init(true, keyParam);

            var response = new byte[16];
            int blockSize = engine.GetBlockSize();
            for (int offset = 0; offset < challenge.Length; offset += blockSize)
            {
                engine.ProcessBlock(challenge, offset, response, offset);
            }    



            return response;
        }

        /// <summary>
        /// Creates an enhanced Ultra authentication response with username and password.
        /// </summary>
        /// <param name="secretKey">The shared secret key between client and server.</param>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns>The enhanced authentication response.</returns>
        private static byte[] CreateEnhancedUltraResponse(byte[] secretKey, string username, string password)
        {
            if(String.IsNullOrEmpty(username)) throw new ArgumentNullException(nameof(username));
            if(String.IsNullOrEmpty(password)) throw new ArgumentNullException(nameof(password));
            if(secretKey.Length != 8) throw new ArgumentException("Secret key must be 8 bytes long in UltraVNC implementation.", nameof(secretKey));

            //Trim username and password to max lengths, add null terminator to work with random filled buffers
            var userBytes = Encoding.UTF8.GetBytes((username+'\0'));
            var passBytes = Encoding.UTF8.GetBytes(password+'\0');

            var vncUserBytes = new byte[USERLENGTH];
            var vncPassBytes = new byte[PASSLENGTH];

            //Fill with random data to avoid predictable padding

            var randomGenerator = new SecureRandom();
            randomGenerator.NextBytes(vncUserBytes);
            randomGenerator.NextBytes(vncPassBytes);

            //RandomNumberGenerator.Fill(vncUserBytes);
            //RandomNumberGenerator.Fill(vncPassBytes);

            Array.Copy(userBytes, vncUserBytes, Math.Min(userBytes.Length, USERLENGTH));
            Array.Copy(passBytes, vncPassBytes, Math.Min(passBytes.Length, PASSLENGTH));

            // Clear original arrays
            Array.Clear(userBytes, 0, userBytes.Length);
            Array.Clear(passBytes, 0, passBytes.Length);

            // Prepare DES key from shared secret
            byte[] desKey = PrepareDesKey(secretKey);
            byte[] reversedSecretKey = ReverseBitOrder(secretKey);
            // Encrypt challenge
            //using var desProvider = DES.Create();
            //desProvider.Key = desKey;
            //desProvider.Mode = CipherMode.CBC;
            //desProvider.Padding = PaddingMode.None;

            // var response = new byte[USERLENGTH + PASSLENGTH];

            //desProvider.IV = secretKey;
            //using (var encUser = desProvider.CreateEncryptor())
            //{
            //    // one shot is fine since length is multiple of 8
            //    encUser.TransformBlock(vncUserBytes, 0, USERLENGTH, response, 0);
            //}

            //desProvider.IV = secretKey;
            //using (var encUser = desProvider.CreateEncryptor())
            //{
            //    // one shot is fine since length is multiple of 8
            //    encUser.TransformBlock(vncPassBytes, 0, PASSLENGTH, response, USERLENGTH);
            //}


            var desEngine = new DesEngine();
            var cbcBlockCipher = new CbcBlockCipher(desEngine);
            var keyParam = new KeyParameter(desKey);
            var keyParamWithIV = new ParametersWithIV(keyParam, secretKey);

            byte[] response = new byte[USERLENGTH + PASSLENGTH];

            // --- Szyfrowanie USER ---
            cbcBlockCipher.Init(true, keyParamWithIV);
            for (int i = 0; i < USERLENGTH; i += 8)
            {
                cbcBlockCipher.ProcessBlock(vncUserBytes, i, response, i);
            }

            // --- Szyfrowanie PASS ---
            // Ponowna inicjalizacja resetuje IV (kluczowe dla UltraVNC)
            cbcBlockCipher.Init(true, keyParamWithIV);
            for (int i = 0; i < PASSLENGTH; i += 8)
            {
                cbcBlockCipher.ProcessBlock(vncPassBytes, i, response, USERLENGTH + i);
            }

            return response;
        }

        private static byte ReverseByteBits(byte value)
        {
            byte result = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((value & (1 << i)) != 0)
                    result |= (byte)(0x80 >> i);
            }
            return result;
        }

        private static int CountBits(byte b)
        {
            // simple popcount for a byte
            int count = 0;
            while (b != 0)
            {
                count += b & 1;
                b >>= 1;
            }
            return count;
        }

        static byte[] PrepareDesKey(byte[] secretKey)
        {
            if(secretKey.Length != 8) throw new ArgumentException("Secret key must be 8 bytes long in UltraVNC implementation.", nameof(secretKey));

            byte[] key = new byte[8];

            Buffer.BlockCopy(secretKey, 0, key, 0, 8);

            // bit-reversal
            for (int i = 0; i < 8; i++) key[i] = ReverseByteBits(key[i]);

            // DES odd parity
            for (int i = 0; i < 8; i++)
            {
                int upper7 = key[i] >> 1;
                int ones = CountBits((byte)upper7);
                key[i] = (byte)((ones & 1) == 0 ? (key[i] | 0x01) : (key[i] & 0xFE));
            }

            return key;
        }

        static byte[] ReverseBitOrder(byte[] input)
        {
            byte[] output = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                byte value = input[i];
                byte newValue = 0;
                for (int offset = 0; offset < 8; offset++)
                {
                    if ((value & (0b1 << offset)) != 0)
                        newValue |= (byte)(0b10000000 >> offset);
                }
                output[i] = newValue;
            }
            return output;
        }
    }
}
