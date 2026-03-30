using System;
using System.IO;
using ElectionGuard.Decryption.ElectionRecord;
using ElectionGuard.Decryption.Verify;

namespace ElectionGuard.CLI.Encrypt
{
    /// <summary>
    /// Verify an Election Record.
    ///
    /// <para>
    /// The verification logic delegates to <see cref="VerifyElection.VerifyAsync"/> which
    /// implements the checks defined in the ElectionGuard specification.
    /// </para>
    ///
    /// <para><b>v2.1 verification items (TODO)</b> – The following checks are required by the
    /// v2.1 spec and are not yet fully implemented in the underlying verifier:</para>
    /// <list type="bullet">
    ///   <item>
    ///     <b>V2.1-1 – Triple guardian key pairs</b>: Verify that each guardian committed to
    ///     three key pairs (K_i, K_hat_i, kappa_i) and that the joint keys K and K_hat are
    ///     the products of the respective per-guardian keys.
    ///   </item>
    ///   <item>
    ///     <b>V2.1-2 – Hash chain (H_P / H_B / H_E)</b>: Verify that the election context
    ///     hash chain was produced by <c>MakeV21</c> (i.e., H_P uses the full parameter set
    ///     including K_hat, H_B covers raw manifest bytes, H_E incorporates K_hat).
    ///   </item>
    ///   <item>
    ///     <b>V2.1-3 – Unified range proofs</b>: Verify that ballot selection proofs use the
    ///     unified Σ-proof structure (single challenge / response pair covering both selection
    ///     and vote-limit bounds) instead of the separate selection + limit proofs from v2.0.
    ///   </item>
    ///   <item>
    ///     <b>V2.1-4 – Commit-to-commitment decryption proofs</b>: Verify guardian decryption
    ///     proofs that bind to the polynomial commitment rather than the raw secret.
    ///   </item>
    ///   <item>
    ///     <b>V2.1-5 – Contest data encryption with K_hat</b>: Verify that each contest's
    ///     extended data field is encrypted under the joint data key K_hat (not the vote key K),
    ///     and that the corresponding decryption proof is valid.
    ///   </item>
    ///   <item>
    ///     <b>V2.1-6 – Extended-data decryption correctness</b>: Corresponds to spec
    ///     Verification 11 / 14 which are currently marked TODO in <see cref="VerifyElection"/>.
    ///   </item>
    /// </list>
    /// </summary>
    internal class VerifyCommand
    {
        public static Task Execute(VerifyOptions options)
        {
            try
            {
                var command = new VerifyCommand();
                return command.ExecuteInternal(options);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                throw;
            }
        }

        private async Task ExecuteInternal(VerifyOptions options)
        {
            options.Validate();

            if (string.IsNullOrEmpty(options.ZipFile))
            {
                throw new ArgumentNullException(nameof(options.ZipFile));
            }

            var electionRecord = await ElectionRecordManager.ImportAsync(options.ZipFile);
            var results = await VerifyElection.VerifyAsync(electionRecord);

            Console.WriteLine(results.ToString(options.Verbose));

            // TODO (v2.1): The checks above use the v2.0 proof structures.  Once
            // VerifyElection is updated for v2.1 (unified range proofs,
            // commit-to-commitment decryption proofs, K_hat-encrypted contest data)
            // this command will automatically exercise those paths.  See the
            // class-level XML doc for the full list of v2.1 verification items.

            Console.WriteLine(
                $"All checks are complete. The election record is {(results.AllValid ? "valid" : "invalid")}");
        }
    }
}
