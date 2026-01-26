using MarcusW.VncClient.Protocol.SecurityTypes;
using MarcusW.VncClient.Security;
using MarcusW.VncClient.Utils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Buffers.Binary;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection.Metadata;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MarcusW.VncClient.Protocol.Implementation.SecurityTypes
{
    /// <summary>
    /// A security type that implements RA2ne (RSA-AES without encryption) authentication.
    /// This provides RSA authentication but without transport encryption.
    /// </summary>
    public class Ra2neSecurityType : ISecurityType
    {
        private readonly RfbConnectionContext _context;

        /// <inheritdoc />
        public byte Id => (byte)WellKnownSecurityType.RA2ne;

        /// <inheritdoc />
        public string Name => "RA2ne";

        /// <inheritdoc />
        public int Priority => 50; // Lower than RA2 due to lack of encryption

        /// <summary>
        /// Specifies the max password length for UltraVNC enhanced authentication.
        /// </summary>
        private const int PASSLENGTH = 64;
        /// <summary>
        /// Specifies the max (domain and) username length for UltraVNC enhanced authentication.
        /// </summary>
        private const int USERLENGTH = 256;

        public int ClientKeyBits => 2048;

        private byte[] _srvSessionKey;

        private byte[] _cliSessionKey;

        private byte[] _cliMsgCounter = new byte[16];

        private byte[] _srvMsgCounter = new byte[16];

        private IAsymmetricBlockCipher _serverEncryptor;

        private IAsymmetricBlockCipher _clientDecryptor;

        private byte[] _serverKey;
        private byte[] _clientKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="Ra2neSecurityType"/>.
        /// </summary>
        /// <param name="context">The connection context.</param>
        public Ra2neSecurityType(RfbConnectionContext context)
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

            // RA2ne uses RSA/AES-128 without establishing an encrypted tunnel.
            // We still perform the same RSA/AES key exchange as RA2, but only use it
            // to protect the credential blob.

            //=======================================================================================
            //STEP1: Receive server RSA key
            //=======================================================================================

            // Read key length (4 bytes, big-endian)
            var keyLengthBuffer = new byte[4];
            await transport.Stream.ReadExactlyAsync(keyLengthBuffer, cancellationToken).ConfigureAwait(false);
            var serverKeyLength = BinaryPrimitives.ReadUInt32BigEndian(keyLengthBuffer);
            if (serverKeyLength <1024|| serverKeyLength > 8192)
                throw new InvalidOperationException($"Invalid RSA key length: {serverKeyLength}");

            //RSA n - modulus
            //RSA e - exponent
            var serverKeyBuffer = new byte[(int)serverKeyLength / 8 * 2]; // modulus + exponent
            await transport.Stream.ReadExactlyAsync(serverKeyBuffer, cancellationToken).ConfigureAwait(false);
            
            var serverModulus = serverKeyBuffer[..(serverKeyBuffer.Length / 2)]; //first half with modulus
            var serverExponent = serverKeyBuffer[(serverKeyBuffer.Length / 2)..]; //second half with exponent

            var serverModulusBigInt = new BigInteger(1, serverModulus, true);
            var serverExponentBigInt = new BigInteger(1, serverExponent, true);

            RsaKeyParameters serverRsaKeyParams = new RsaKeyParameters(
                isPrivate: false,
                modulus: serverModulusBigInt,
                exponent: serverExponentBigInt
                );

            var serverRsaEngine = new RsaEngine();
            _serverEncryptor = new Pkcs1Encoding(serverRsaEngine);
            _serverEncryptor.Init(forEncryption: true, parameters: serverRsaKeyParams);

            _serverKey = new byte[4 + serverKeyBuffer.Length];
            Buffer.BlockCopy(keyLengthBuffer, 0, _serverKey, 0, 4);
            Buffer.BlockCopy(serverModulus, 0, _serverKey, 4, serverModulus.Length);
            Buffer.BlockCopy(serverExponent, 0, _serverKey, 4 + serverModulus.Length, serverExponent.Length);

            // TODO: optionally ask user to accept key/fingerprint? What if this is used in ThinClient-like mode?

            //=======================================================================================
            //STEP2: Generate client RSA key and send to server
            //=======================================================================================

            var clientRsaKeyGen = new RsaKeyPairGenerator();
            clientRsaKeyGen.Init(new KeyGenerationParameters(new SecureRandom(), ClientKeyBits));
            var clientKeyPair = clientRsaKeyGen.GenerateKeyPair();

            var clientRsaPublicKey = (RsaKeyParameters)clientKeyPair.Public;

            var clientModulus = clientRsaPublicKey.Modulus.ToByteArrayUnsigned();
            var clientExponent = clientRsaPublicKey.Exponent.ToByteArrayUnsigned();

            var clientKeyLength = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(clientKeyLength, (uint)(ClientKeyBits));

            clientModulus = ToFixedLengthArray(clientModulus,ClientKeyBits / 8);
            clientExponent = ToFixedLengthArray(clientExponent, ClientKeyBits / 8);

            var clientRsaEngine = new RsaEngine();
            _clientDecryptor = new Pkcs1Encoding(clientRsaEngine);
            _clientDecryptor.Init(forEncryption: false, parameters: clientKeyPair.Private);

            _clientKey = new byte[4 + clientModulus.Length + clientExponent.Length];
            Buffer.BlockCopy(clientKeyLength, 0, _clientKey, 0, 4);
            Buffer.BlockCopy(clientModulus, 0, _clientKey, 4, clientModulus.Length);
            Buffer.BlockCopy(clientExponent, 0, _clientKey, 4 + clientModulus.Length, clientExponent.Length);

            // Send key to server
            await transport.Stream.WriteAsync(_clientKey, cancellationToken).ConfigureAwait(false);

            //=======================================================================================
            //STEP 3: Generate client random and send to server encrypted with server RSA key.
            //=======================================================================================
            byte[] clientRandomBytes = new byte[16]; //16 for Ra2ne, 32 for Ra2ne-256

            var randomGenerator = new SecureRandom();
            randomGenerator.NextBytes(clientRandomBytes);

            var clientRandomEncrypted = _serverEncryptor.ProcessBlock(clientRandomBytes, 0, clientRandomBytes.Length);

            // Send client random length and data
            var cliRandomEncLength = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(cliRandomEncLength, (ushort)clientRandomEncrypted.Length);
            await transport.Stream.WriteAsync(cliRandomEncLength, cancellationToken).ConfigureAwait(false);
            await transport.Stream.WriteAsync(clientRandomEncrypted, cancellationToken).ConfigureAwait(false);

            //=======================================================================================
            //STEP 4: Receive server random encrypted with client RSA key.
            //=======================================================================================
            var srvRandomEncLenBuf = new byte[2];
            await transport.Stream.ReadExactlyAsync(srvRandomEncLenBuf, cancellationToken).ConfigureAwait(false);
            var srvRandomEncLength = BinaryPrimitives.ReadUInt16BigEndian(srvRandomEncLenBuf);
            if (srvRandomEncLength <= 0 || srvRandomEncLength > 4096)
                throw new InvalidOperationException($"Invalid RA2ne encrypted block length: {srvRandomEncLength}");

            var srvRandomEncBytes = new byte[srvRandomEncLength];
            await transport.Stream.ReadExactlyAsync(srvRandomEncBytes, cancellationToken).ConfigureAwait(false);

            byte[] serverRandomBytes = _clientDecryptor.ProcessBlock(srvRandomEncBytes, 0, srvRandomEncBytes.Length);

            //=======================================================================================
            // Step 5: Generate Session key from hashing client and server random values.
            //=======================================================================================
            var randomCliSrv = new byte[serverRandomBytes.Length + clientRandomBytes.Length];
            Array.Copy(serverRandomBytes, 0, randomCliSrv, 0, serverRandomBytes.Length);
            Array.Copy(clientRandomBytes, 0, randomCliSrv, serverRandomBytes.Length, clientRandomBytes.Length);

            var randomSrvCli = new byte[clientRandomBytes.Length + serverRandomBytes.Length];
            Array.Copy(clientRandomBytes, 0, randomSrvCli, 0, clientRandomBytes
                .Length);
            Array.Copy(serverRandomBytes, 0, randomSrvCli, clientRandomBytes.Length, serverRandomBytes.Length);

            var clientSessionHash = new Sha1Digest();
            var serverSessionHash = new Sha1Digest();

            clientSessionHash.BlockUpdate(randomCliSrv, 0, randomCliSrv.Length);
            serverSessionHash.BlockUpdate(randomSrvCli, 0, randomSrvCli.Length);
            var clientSessionHashResult = new byte[clientSessionHash.GetDigestSize()];
            var serverSessionHashResult = new byte[serverSessionHash.GetDigestSize()];
            clientSessionHash.DoFinal(clientSessionHashResult, 0);
            serverSessionHash.DoFinal(serverSessionHashResult, 0);

            _cliSessionKey = clientSessionHashResult.AsSpan(0, 16).ToArray();
            _srvSessionKey = serverSessionHashResult.AsSpan(0, 16).ToArray();
            //From now all messages should be encrypted width AES-EAX / AES-CTR + CMAC. U16 as message length, next message in U8 array, last 16 bytes is MAC.

            //=======================================================================================
            //Step 6: Exchange hashes generated from public client and server keys.
            //=======================================================================================

            var keysServerClient = new byte[_serverKey.Length + _clientKey.Length];
            var keysClientServer = new byte[_serverKey.Length + _clientKey.Length];

            Array.Copy(_serverKey, 0, keysServerClient, 0, _serverKey.Length);
            Array.Copy(_clientKey, 0, keysServerClient, _serverKey.Length, _clientKey.Length);

            Array.Copy(_clientKey, 0, keysClientServer, 0, _clientKey.Length);
            Array.Copy(_serverKey, 0, keysClientServer, _clientKey.Length, _serverKey.Length);

            var serverKeysHash = new Sha1Digest();
            var clientKeysHash = new Sha1Digest();

            serverKeysHash.BlockUpdate(keysServerClient, 0, keysServerClient.Length);
            clientKeysHash.BlockUpdate(keysClientServer, 0, keysClientServer.Length);

            var serverKeysHashResult = new byte[serverKeysHash.GetDigestSize()];
            var clientKeysHashResult = new byte[clientKeysHash.GetDigestSize()];

            serverKeysHash.DoFinal(serverKeysHashResult);
            clientKeysHash.DoFinal(clientKeysHashResult);
            var clientHashMessage = MakeMessage(clientKeysHashResult);

            await transport.Stream.WriteAsync(clientHashMessage, cancellationToken).ConfigureAwait(false);

            var serverHashBuffer = new byte[2 + 20 + 16];
            await transport.Stream.ReadExactlyAsync(serverHashBuffer, cancellationToken).ConfigureAwait(false);
            var serverHashMessage = ReadMessage(serverHashBuffer);
            if (!serverHashMessage.SequenceEqual(serverKeysHashResult))
                throw new InvalidOperationException("Server hash does not match expected value.");

            //=======================================================================================
            //Step 7: Get subtype from server (1 - username/password, 2 - only password)
            //=======================================================================================
            // Plaintext is: 1 byte as username length (0 for subtype 2), username as UTF-8, password as UTF-8, u8 array with data, 1 byte for password length, u8 array for data

            var subtypeBuffer = new byte[2 + 1 + 16];
            await transport.Stream.ReadExactlyAsync(subtypeBuffer, cancellationToken).ConfigureAwait(false);
            var subtypeMessage = ReadMessage(subtypeBuffer);

            if (subtypeMessage == null)
                throw new ArgumentNullException("RA2ne subtype is null.");

            if (subtypeMessage[0] != 1 && subtypeMessage[0] != 2)
                throw new InvalidOperationException($"Invalid RA2ne subtype: {subtypeMessage[0]}");

            //=======================================================================================
            // Step 8: Get credentials from user and send to server
            //=======================================================================================

            byte[] credentials;

            if (subtypeMessage[0] == 1)
            {
                // Username/password
                CredentialsAuthenticationInput creds = await authenticationHandler
                    .ProvideAuthenticationInputAsync(_context.Connection, this, new CredentialsAuthenticationInputRequest()).ConfigureAwait(false);

                if (creds == null || string.IsNullOrEmpty(creds.Username) || string.IsNullOrEmpty(creds.Password))
                    throw new InvalidOperationException("No credentials provided for RA2ne authentication.");
                if (creds.Username.Length > USERLENGTH)
                    throw new InvalidOperationException($"Username too long for RA2ne authentication (max {USERLENGTH} characters).");
                if (creds.Password.Length > PASSLENGTH)
                    throw new InvalidOperationException($"Password too long for RA2ne authentication (max {PASSLENGTH} characters).");

                credentials=new byte[1 + creds.Username.Length + 1 + creds.Password.Length];
                credentials[0] = (byte)creds.Username.Length;
                Encoding.UTF8.GetBytes(creds.Username, 0, creds.Username.Length, credentials, 1);
                credentials[1 + creds.Username.Length] = (byte)creds.Password.Length;
                Encoding.UTF8.GetBytes(creds.Password, 0, creds.Password.Length, credentials, 1 + creds.Username.Length + 1);

            }
            else
            {
                // Only password
                PasswordAuthenticationInput pass = await authenticationHandler
                    .ProvideAuthenticationInputAsync(_context.Connection, this, new PasswordAuthenticationInputRequest()).ConfigureAwait(false);

                if (pass.Password == null || string.IsNullOrEmpty(pass.Password))
                {
                    throw new InvalidOperationException("No password provided for RA2ne authentication.");
                }
                if (pass.Password.Length > PASSLENGTH)
                    throw new InvalidOperationException($"Password too long for RA2ne authentication (max {PASSLENGTH} characters).");
                credentials = new byte[2+ pass.Password.Length];
                credentials[0] = 0; // username length = 0
                credentials[1] = (byte)pass.Password.Length;
                Encoding.UTF8.GetBytes(pass.Password, 0, pass.Password.Length, credentials, 2);
            }

            var credentialMessage = MakeMessage(credentials);

            await transport.Stream.WriteAsync(credentialMessage, cancellationToken).ConfigureAwait(false);

            return new AuthenticationResult(tunnelTransport: null, expectSecurityResult: true);
        }

        /// <inheritdoc />
        public Task ReadServerInitExtensionAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        private static byte[] ToFixedLengthArray(byte[] data, int size)
        {
            if (data.Length == size)
                return data;
            var result = new byte[size];
            if (data.Length < size)
            {
                //copy to the end
                Buffer.BlockCopy(data, 0, result, size - data.Length, data.Length);
            }
            else
            {
                // copy the beginning
                Buffer.BlockCopy(data, 0, result, 0, size);
            }
            return result;
        }

        private byte[] MakeMessage(byte[] plainData)
        {
            ArgumentNullException.ThrowIfNull(plainData);

            // Associated data: 2-byte big-endian plaintext length; stays in clear
            var ad = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(ad, (ushort)plainData.Length);

            var cipher = new EaxBlockCipher(new AesEngine());
            var keyParam = new KeyParameter(_cliSessionKey);

            var aeadParameters = new AeadParameters(keyParam, 128, _cliMsgCounter, ad);

            cipher.Init(true, aeadParameters);

            byte[] cipherData = new byte[cipher.GetOutputSize(plainData.Length)];
            int len = cipher.ProcessBytes(plainData, 0, plainData.Length, cipherData, 0);
            cipher.DoFinal(cipherData, len);

            for (int i = 0; i < _cliMsgCounter.Length; i++)
            {
                if (_cliMsgCounter[i] < 255)
                {
                    _cliMsgCounter[i]++;
                    break; 
                }
                else
                {
                    _cliMsgCounter[i] = 0;
                }
            }

            // Output message layout: AD || ciphertext+tag
            byte[] message = new byte[ad.Length + cipherData.Length];
            int pos = 0;
            ad.CopyTo(message.AsSpan(pos));
            pos += ad.Length;
            Buffer.BlockCopy(cipherData, 0, message, pos, cipherData.Length);
            return message;
        }

        private byte[] ReadMessage(byte[] message)
        {
            ArgumentNullException.ThrowIfNull(message);
            if (message.Length < 2 + 16) // at least AD + tag
                throw new InvalidOperationException("Invalid encrypted message length.");
            // Associated data: 2-byte big-endian plaintext length; stays in clear
            var ad = new byte[2];
            Buffer.BlockCopy(message, 0, ad, 0, 2);
            ushort plainLength = BinaryPrimitives.ReadUInt16BigEndian(ad);

            var cipher = new EaxBlockCipher(new AesEngine());
            var keyParam = new KeyParameter(_srvSessionKey);
            var aeadParameters = new AeadParameters(keyParam, 128, _srvMsgCounter, ad);
            cipher.Init(false, aeadParameters);
            byte[] plainData = new byte[cipher.GetOutputSize(message.Length - ad.Length)];
            int len = cipher.ProcessBytes(message, ad.Length, message.Length - ad.Length, plainData, 0);
            cipher.DoFinal(plainData, len);
            for (int i = 0; i < _srvMsgCounter.Length; i++)
            {
                if (_srvMsgCounter[i] < 255)
                {
                    _srvMsgCounter[i]++;
                    break;
                }
                else
                {
                    _srvMsgCounter[i] = 0;
                }
            }
            if (plainData.Length != plainLength)
                throw new InvalidOperationException("Decrypted message length does not match expected length.");
            return plainData;
        }
    }
}
