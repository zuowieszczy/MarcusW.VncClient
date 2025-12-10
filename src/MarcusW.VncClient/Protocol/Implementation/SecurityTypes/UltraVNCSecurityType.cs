using MarcusW.VncClient.Protocol.SecurityTypes;
using MarcusW.VncClient.Security;
using MarcusW.VncClient.Utils;
using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Numerics;

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
            var modeMem = await transport.Stream.ReadAllAsync(6, cancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte> auth = modeMem.Slice(5,1); //2 = Ultra mode with 2 passwords (normal & viewonly), 113 = MSLogonII mode

            // Enhanced Ultra authentication with MS Logon support
            await transport.Stream.WriteAsync(auth, cancellationToken).ConfigureAwait(false);

            //Standard UltraVNC authentication
            if (auth.Span[0] == 2)
            {
                // Read challenge from server (16 bytes)
                var challengeMem = await transport.Stream.ReadAllAsync(16, cancellationToken).ConfigureAwait(false);
                byte[] challengeBuffer = challengeMem.ToArray();

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
            else if (auth.Span[0] == 113)
            {
                // Read DH params (8-byte big-endian each)
                var genBytes = (await transport.Stream.ReadAllAsync(8, cancellationToken)).ToArray();
                var modBytes = (await transport.Stream.ReadAllAsync(8, cancellationToken)).ToArray();
                var pubBytes = (await transport.Stream.ReadAllAsync(8, cancellationToken)).ToArray();

                // Build BigIntegers as unsigned big-endian
                var generatorInt = new BigInteger(genBytes, isUnsigned: true, isBigEndian: true);
                var modulusInt = new BigInteger(modBytes, isUnsigned: true, isBigEndian: true);
                var pubvalInt = new BigInteger(pubBytes, isUnsigned: true, isBigEndian: true);

                Debug.WriteLine($"g={generatorInt}, m={modulusInt}, p={modulusInt}");

                // Generate PrivateX
                byte[] xBytes = new byte[8];
                using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(xBytes);
                var privateX = new BigInteger(xBytes, isUnsigned: true, isBigEndian: true);
                if (privateX.IsZero) privateX = BigInteger.One;
                privateX %= (modulusInt - BigInteger.One);
                if (privateX.IsZero) privateX = BigInteger.One;
                Debug.WriteLine($"X={privateX}");

                // Compute client public B = g^x mod p
                var publicB = BigInteger.ModPow(generatorInt, privateX, modulusInt);
                Debug.WriteLine($"B={publicB}");

                // Send publicB as 8-byte big-endian
                byte[] publicBBytes = new byte[8];
                WriteBigEndianU64(publicB, publicBBytes);
                await transport.Stream.WriteAsync(publicBBytes, cancellationToken).ConfigureAwait(false);

                // Compute shared secret S = A^x mod p
                var sharedSecret = BigInteger.ModPow(pubvalInt, privateX, modulusInt);
                Debug.WriteLine($"Secret={sharedSecret}");

                // Export secret as 8-byte big-endian
                byte[] sharedSecretByte = new byte[8];
                WriteBigEndianU64(sharedSecret, sharedSecretByte);

                CredentialsAuthenticationInput input = await authenticationHandler
                    .ProvideAuthenticationInputAsync(_context.Connection, this, new CredentialsAuthenticationInputRequest()).ConfigureAwait(false);

                byte[] response = CreateEnhancedUltraResponse(sharedSecretByte, input.Username, input.Password);

                await transport.Stream.WriteAsync(response, cancellationToken).ConfigureAwait(false);

                return new AuthenticationResult();
            }
            else
            {
                throw new NotSupportedException($"Ultra authentication mode {auth.Span[0]} is not supported by {this.Name}.");
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

            // Reverse bit order of all byes in key
            for (var i = 0; i < key.Length; i++)
            {
                byte value = key[i];
                byte newValue = 0;
                for (var offset = 0; offset < 8; offset++)
                {
                    if ((value & (0b1 << offset)) != 0)
                        newValue |= (byte)(0b10000000 >> offset);
                }

                key[i] = newValue;
            }

            // Encrypt challenge
            using var desProvider = DES.Create();
            desProvider.Key = key;
            desProvider.Mode = CipherMode.ECB;
            desProvider.Padding = PaddingMode.None;
            using var encryptor = desProvider.CreateEncryptor();

            // Encrypt challenge with key
            var response = new byte[16];
            encryptor.TransformBlock(challenge.ToArray(), 0, challenge.Length, response, 0);

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

            //FIll with random data to avoid predictable padding
            RandomNumberGenerator.Fill(vncUserBytes);
            RandomNumberGenerator.Fill(vncPassBytes);

            Array.Copy(userBytes, vncUserBytes, Math.Min(userBytes.Length, USERLENGTH));
            Array.Copy(passBytes, vncPassBytes, Math.Min(passBytes.Length, PASSLENGTH));

            // Clear original arrays
            Array.Clear(userBytes, 0, userBytes.Length);
            Array.Clear(passBytes, 0, passBytes.Length);

            // Prepare DES key from shared secret
            byte[] desKey = PrepareDesKey(secretKey);
            // Encrypt challenge
            using var desProvider = DES.Create();
            desProvider.Key = desKey;
            desProvider.Mode = CipherMode.CBC;
            desProvider.Padding = PaddingMode.None;

            var response = new byte[USERLENGTH + PASSLENGTH];

            desProvider.IV = secretKey;
            using (var encUser = desProvider.CreateEncryptor())
            {
                // one shot is fine since length is multiple of 8
                encUser.TransformBlock(vncUserBytes, 0, USERLENGTH, response, 0);
            }

            desProvider.IV = secretKey;
            using (var encUser = desProvider.CreateEncryptor())
            {
                // one shot is fine since length is multiple of 8
                encUser.TransformBlock(vncPassBytes, 0, PASSLENGTH, response, USERLENGTH);
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
        static void WriteBigEndianU64(BigInteger value, byte[] dest8)
        {
            // Reduce to 64-bit (unsigned) and write big-endian
            ulong v = (ulong)(value & ((BigInteger)ulong.MaxValue));
            BinaryPrimitives.WriteUInt64BigEndian(dest8, v);
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
    }
}
