using System;
using System.IO;
using System.Text;

namespace ElectionGuard.CLI.Encrypt
{
    /// <summary>
    /// Create an Election Package.
    ///
    /// Supports two modes:
    /// <list type="bullet">
    ///   <item><b>v1.x (legacy)</b> – provide <c>--commitment</c> and <c>--publicKey</c>;
    ///         context is built with the standard <see cref="CiphertextElectionContext"/> constructor.</item>
    ///   <item><b>v2.1</b> – provide <c>--ballot-data-key</c> (K_hat) and <c>--publicKey</c> (K);
    ///         context is built with <see cref="CiphertextElectionContext.MakeV21"/> which computes
    ///         H_P, H_B, and H_E per the v2.1 spec from raw manifest bytes.</item>
    /// </list>
    /// </summary>
    internal class CreateElectionCommand
    {
        public static Task Execute(CreateElectionOptions options)
        {
            try
            {
                var command = new CreateElectionCommand();
                return command.ExecuteInternal(options);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                throw;
            }
        }

        private Task ExecuteInternal(CreateElectionOptions options)
        {
            Console.WriteLine(options.IsV21 ? "Create Election (v2.1)" : "Create Election (v1.x)");

            options.Validate();

            if (string.IsNullOrEmpty(options.Manifest))
            {
                throw new ArgumentNullException(nameof(options.Manifest));
            }

            Console.WriteLine($"Loading Manifest {options.Manifest}");
            var manifestJson = File.ReadAllText(options.Manifest);

            Console.WriteLine("Parsing Manifest");
            var manifest = new Manifest(manifestJson);

            CiphertextElectionContext context;

            if (options.IsV21)
            {
                // ── v2.1 path ────────────────────────────────────────────────────
                // MakeV21 derives H_P (parameter hash), H_B (base hash), and
                // H_E (extended base hash) from raw manifest bytes per spec §3.
                // The caller supplies both the joint vote key K and the joint
                // ballot-data key K_hat (produced by the key-ceremony command).
                Console.WriteLine("Building v2.1 context (MakeV21)");

                var elGamalPublicKey = new ElementModP(options.ElGamalPublicKey);
                var ballotDataPublicKey = new ElementModP(options.BallotDataPublicKey);
                var manifestBytes = Encoding.UTF8.GetBytes(manifestJson);

                context = CiphertextElectionContext.MakeV21(
                    (ulong)options.NumberOfGuardians,
                    (ulong)options.Quorum,
                    elGamalPublicKey,
                    ballotDataPublicKey,
                    manifestBytes);

                Console.WriteLine($"  H_B (base hash):     {context.CryptoBaseHash}");
                Console.WriteLine($"  H_E (extended hash): {context.CryptoExtendedBaseHash}");
            }
            else
            {
                // ── v1.x (legacy) path ───────────────────────────────────────────
                Console.WriteLine("Loading Internal Manifest");
                var internalManifest = new InternalManifest(manifest);

                Console.WriteLine("Building v1.x context");
                var commitmentHash = new ElementModQ(options.CommitmentHash);
                var publicKey = new ElementModP(options.ElGamalPublicKey);

                context = new CiphertextElectionContext(
                    (ulong)options.NumberOfGuardians, (ulong)options.Quorum,
                    publicKey, commitmentHash, internalManifest.ManifestHash);
            }

            Console.WriteLine("Saving Files");

            // Write the election package to the output directory
            File.WriteAllText(Path.Join(options.OutDir, "context.json"), context.ToJson());
            File.WriteAllText(Path.Join(options.OutDir, "manifest.json"), manifest.ToJson());

            Console.WriteLine("Create Election Complete");
            return Task.CompletedTask;
        }
    }
}
