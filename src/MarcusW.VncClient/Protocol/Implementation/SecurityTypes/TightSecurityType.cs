using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MarcusW.VncClient.Protocol.SecurityTypes;
using MarcusW.VncClient.Security;
using MarcusW.VncClient.Utils;

namespace MarcusW.VncClient.Protocol.Implementation.SecurityTypes
{
    /// <summary>
    /// Tight security type (RFB security type 16) with optional tunneling and sub‑authentication methods,
    /// compatible with TightVNC / LibVNC.
    /// </summary>
    public class TightSecurityType : ISecurityType
    {
        private readonly RfbConnectionContext _context;

        /// <inheritdoc />
        public byte Id => (byte)WellKnownSecurityType.Tight;

        /// <inheritdoc />
        public string Name => "Tight";

        /// <inheritdoc />
        public int Priority => 20;

        /// <summary>
        /// Initializes a new instance of the <see cref="TightSecurityType"/>.
        /// </summary>
        /// <param name="context">The connection context.</param>
        public TightSecurityType(RfbConnectionContext context)
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
            Stream stream = transport.Stream;

            //
            // 1. Tunneling negotiation (TightVNC style, 1‑byte fields)
            //
            // Server: 1 byte - number of tunnel types (N)
            //         N bytes - list of tunnel type IDs
            // Client: 1 byte - chosen tunnel type
            //

            byte[] singleByteBuffer = new byte[1];

            // Read number of supported tunneling types (4 bytes) (Uint32 on TightVNC 2.8.85 source code)
            ReadOnlyMemory<byte> tunnelCountMem = await stream.ReadAllAsync(4, cancellationToken).ConfigureAwait(false);
            byte tunnelCount = tunnelCountMem.Span[3];

            var tunnelTypes = new List<byte>(tunnelCount);
            if (tunnelCount > 0)
            {
                ReadOnlyMemory<byte> tunnelTypesMem = await stream.ReadAllAsync(tunnelCount, cancellationToken).ConfigureAwait(false);
                tunnelTypes.AddRange(tunnelTypesMem.ToArray());

                // Choose preferred tunneling type (0 = no tunneling)
                byte chosenTunnelType = ChoosePreferredTunnelType(tunnelTypes);

                // Send chosen tunneling type (1 byte)
                byte[] tunnelOutput = new byte[4];
                tunnelOutput[3] = chosenTunnelType;
                await stream.WriteAsync(tunnelOutput, cancellationToken).ConfigureAwait(false);

                // If non‑zero tunnel was chosen, we would need to establish the tunnel now.
                // This implementation only supports "no tunneling".
                if (chosenTunnelType != 0)
                    throw new NotSupportedException($"Tight tunneling type {chosenTunnelType} is not supported.");
            }


            //
            // 2. Authentication type negotiation (TightVNC style, 1‑byte fields)
            //
            // Server: 1 byte - number of auth types (M)
            //         M bytes - list of auth type IDs
            // Client: 1 byte - chosen auth type
            //

            // Read number of supported authentication types (4 bytes)
            ReadOnlyMemory<byte> authCountMem = await stream.ReadAllAsync(4, cancellationToken).ConfigureAwait(false);
            byte authCount = authCountMem.Span[3];

            var authTypes = new List<byte>(authCount);
            if (authCount > 0)
            {
                for (int i = 0; i < authCount; i++)
                {
                    ReadOnlyMemory<byte> authTypeMem = await stream.ReadAllAsync(16, cancellationToken).ConfigureAwait(false);
                    authTypes.Add(authTypeMem.Span[3]);
                }
            }

            // Choose preferred authentication type
            byte chosenAuthType = ChoosePreferredAuthType(authTypes);
            if (chosenAuthType == 0)
                throw new InvalidOperationException("No supported Tight authentication type found.");

            // Send chosen authentication type (1 byte)
            byte[] authOutput = new byte[4];
            authOutput[3] = chosenAuthType;
            singleByteBuffer[0] = chosenAuthType;
            await stream.WriteAsync(authOutput, cancellationToken).ConfigureAwait(false);

            //
            // 3. Perform sub‑authentication
            //
            await PerformTightAuthenticationAsync(stream, chosenAuthType, authenticationHandler, cancellationToken).ConfigureAwait(false);

            // Standard RFB 3.8 SecurityResult (4 bytes) is read later by RfbHandshaker.
            return new AuthenticationResult();
        }

        /// <inheritdoc />
        public Task ReadServerInitExtensionAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        /// <summary>
        /// Chooses the preferred tunneling type from available options.
        /// </summary>
        /// <param name="tunnelTypes">Available tunneling types.</param>
        /// <returns>The chosen tunneling type (0 for no tunneling).</returns>
        private static byte ChoosePreferredTunnelType(IReadOnlyCollection<byte> tunnelTypes)
        {
            // Prefer no tunneling for simplicity (type 0), matching most TightVNC setups.
            if (tunnelTypes.Any(x => x == 0))
            {
                return 0;
            }

            // If server doesn't offer "no tunneling", just pick the first one (likely to fail later).
            return tunnelTypes.FirstOrDefault();
        }

        /// <summary>
        /// Chooses the preferred authentication type from available options.
        /// </summary>
        /// <param name="authTypes">Available authentication types.</param>
        /// <returns>The chosen authentication type.</returns>
        private static byte ChoosePreferredAuthType(IReadOnlyCollection<byte> authTypes)
        {
            // Tight authentication type codes:
            //  1 = None
            //  2 = VNC authentication
            // 16 = Tight authentication (username/password)
            //129 = Unix login authentication

            // Prefer in this order: Tight > VNC > Unix > None
            byte[] preferredOrder = { 16, 2, 129, 1 };

            foreach (byte preferred in preferredOrder)
            {
                if (authTypes.Contains(preferred))
                    return preferred;
            }

            return 0; // No supported type found
        }

        /// <summary>
        /// Performs Tight authentication based on the chosen authentication type.
        /// </summary>
        /// <param name="stream">The transport stream.</param>
        /// <param name="authType">The chosen authentication type.</param>
        /// <param name="authenticationHandler">The authentication handler.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        private async Task PerformTightAuthenticationAsync(Stream stream, byte authType, IAuthenticationHandler authenticationHandler,
            CancellationToken cancellationToken)
        {
            switch (authType)
            {
                case 1: // None
                    // No extra authentication required; SecurityResult will follow.
                    break;

                case 2: // VNC authentication (same as standard VNC auth, but inside Tight)
                    await PerformVncAuthenticationAsync(stream, authenticationHandler, cancellationToken).ConfigureAwait(false);
                    break;

                case 16: // Tight-specific authentication (username/password)
                    await PerformTightSpecificAuthenticationAsync(stream, authenticationHandler, cancellationToken).ConfigureAwait(false);
                    break;

                case 129: // Unix login authentication (username/password)
                    await PerformUnixLoginAuthenticationAsync(stream, authenticationHandler, cancellationToken).ConfigureAwait(false);
                    break;

                default:
                    throw new NotSupportedException($"Tight authentication type {authType} is not supported.");
            }
        }

        /// <summary>
        /// Performs VNC‑style authentication within Tight security.
        /// </summary>
        private async Task PerformVncAuthenticationAsync(Stream stream, IAuthenticationHandler authenticationHandler, CancellationToken cancellationToken)
        {
            // Read challenge (16 bytes)
            ReadOnlyMemory<byte> challengeMem = await stream.ReadAllAsync(16, cancellationToken).ConfigureAwait(false);
            byte[] challengeBuffer = challengeMem.ToArray();

            // Get password
            PasswordAuthenticationInput input = await authenticationHandler
                .ProvideAuthenticationInputAsync(_context.Connection, this, new PasswordAuthenticationInputRequest())
                .ConfigureAwait(false);

            // Create DES response (same as classic VNC auth)
            byte[] response = CreateVncStyleResponse(challengeBuffer, input.Password);

            // Send response
            await stream.WriteAsync(response, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Performs Tight‑specific authentication (rfbTightTightAuth).
        /// </summary>
        private async Task PerformTightSpecificAuthenticationAsync(Stream stream, IAuthenticationHandler authenticationHandler, CancellationToken cancellationToken)
        {
            CredentialsAuthenticationInput input = await authenticationHandler
                .ProvideAuthenticationInputAsync(_context.Connection, this, new CredentialsAuthenticationInputRequest())
                .ConfigureAwait(false);

            byte[] usernameBytes = Encoding.UTF8.GetBytes(input.Username ?? string.Empty);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(input.Password ?? string.Empty);

            if (usernameBytes.Length > byte.MaxValue)
                throw new InvalidOperationException("Tight username must not exceed 255 bytes in length.");
            if (passwordBytes.Length > byte.MaxValue)
                throw new InvalidOperationException("Tight password must not exceed 255 bytes in length.");

            // Send username length (1 byte) and username
            await stream.WriteAsync(new[] { (byte)usernameBytes.Length }, cancellationToken).ConfigureAwait(false);
            if (usernameBytes.Length > 0)
                await stream.WriteAsync(usernameBytes, cancellationToken).ConfigureAwait(false);

            // Send password length (1 byte) and password
            await stream.WriteAsync(new[] { (byte)passwordBytes.Length }, cancellationToken).ConfigureAwait(false);
            if (passwordBytes.Length > 0)
                await stream.WriteAsync(passwordBytes, cancellationToken).ConfigureAwait(false);

            // Clear sensitive data
            Array.Clear(passwordBytes, 0, passwordBytes.Length);
        }

        /// <summary>
        /// Performs Unix login authentication (rfbTightUnixLoginAuth).
        /// </summary>
        private async Task PerformUnixLoginAuthenticationAsync(Stream stream, IAuthenticationHandler authenticationHandler, CancellationToken cancellationToken)
        {
            CredentialsAuthenticationInput input = await authenticationHandler
                .ProvideAuthenticationInputAsync(_context.Connection, this, new CredentialsAuthenticationInputRequest())
                .ConfigureAwait(false);

            byte[] usernameBytes = Encoding.UTF8.GetBytes(input.Username ?? string.Empty);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(input.Password ?? string.Empty);

            if (usernameBytes.Length > byte.MaxValue)
                throw new InvalidOperationException("Unix login username must not exceed 255 bytes in length.");
            if (passwordBytes.Length > byte.MaxValue)
                throw new InvalidOperationException("Unix login password must not exceed 255 bytes in length.");

            // Send username
            await stream.WriteAsync(new[] { (byte)usernameBytes.Length }, cancellationToken).ConfigureAwait(false);
            if (usernameBytes.Length > 0)
                await stream.WriteAsync(usernameBytes, cancellationToken).ConfigureAwait(false);

            // Send password
            await stream.WriteAsync(new[] { (byte)passwordBytes.Length }, cancellationToken).ConfigureAwait(false);
            if (passwordBytes.Length > 0)
                await stream.WriteAsync(passwordBytes, cancellationToken).ConfigureAwait(false);

            // Clear sensitive data
            Array.Clear(passwordBytes, 0, passwordBytes.Length);
        }

        /// <summary>
        /// Creates a VNC‑style DES encrypted response (challenge‑response).
        /// </summary>
        private static byte[] CreateVncStyleResponse(byte[] challenge, string password)
        {
            if (challenge == null)
                throw new ArgumentNullException(nameof(challenge));
            if (challenge.Length != 16)
                throw new ArgumentException("VNC challenge must be exactly 16 bytes long.", nameof(challenge));

            // Use the first 8 characters/bytes of the password as the DES key (ASCII, like TightVNC).
            var key = new byte[8];
            byte[] passwordBytes = Encoding.ASCII.GetBytes(password ?? string.Empty);
            Array.Copy(passwordBytes, key, Math.Min(key.Length, passwordBytes.Length));

            // Reverse bit order of all bytes in key (VNC requirement)
            for (var i = 0; i < key.Length; i++)
            {
                byte value = key[i];
                byte newValue = 0;
                for (var offset = 0; offset < 8; offset++)
                {
                    if ((value & (1 << offset)) != 0)
                        newValue |= (byte)(0x80 >> offset);
                }

                key[i] = newValue;
            }

            // Encrypt challenge with DES (ECB, no padding)
            using var desProvider = DES.Create();
            desProvider.Key = key;
            desProvider.Mode = CipherMode.ECB;
            desProvider.Padding = PaddingMode.None;

            using ICryptoTransform encryptor = desProvider.CreateEncryptor();

            var response = new byte[16];
            encryptor.TransformBlock(challenge, 0, challenge.Length, response, 0);

            // Clear sensitive data
            Array.Clear(key, 0, key.Length);
            Array.Clear(passwordBytes, 0, passwordBytes.Length);

            return response;
        }
    }
}
