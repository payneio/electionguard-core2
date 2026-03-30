using Newtonsoft.Json;

namespace ElectionGuard.CLI.KeyCeremony;

/// <summary>
/// Simulate a v2.1 guardian key ceremony, producing triple key pairs per guardian.
///
/// In the ElectionGuard v2.1 spec each guardian i generates three key pairs:
///   - K_i       : vote encryption public key (used to form the joint election key K)
///   - K_hat_i   : ballot data encryption public key (used to form the joint data key K_hat)
///   - kappa_i   : communication/auxiliary public key (used in guardian-to-guardian channels)
///
/// The joint keys are:
///   K     = K_1 * K_2 * ... * K_n  (mod p)
///   K_hat = K_hat_1 * K_hat_2 * ... * K_hat_n  (mod p)
///
/// These joint keys are then passed to <c>CiphertextElectionContext.MakeV21()</c> to build the
/// election context with v2.1 hash chain (H_P, H_B, H_E).
/// </summary>
internal class KeyCeremonyCommand
{
    public static Task Execute(KeyCeremonyOptions options)
    {
        try
        {
            var command = new KeyCeremonyCommand();
            return command.ExecuteInternal(options);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            throw;
        }
    }

    private Task ExecuteInternal(KeyCeremonyOptions options)
    {
        Console.WriteLine(
            $"v2.1 Key Ceremony: {options.NumberOfGuardians} guardians, quorum {options.Quorum}");
        options.Validate();

        var guardianSummaries = new List<GuardianKeySummary>();
        var voteKeyHexes = new List<string>(options.NumberOfGuardians);
        var dataKeyHexes = new List<string>(options.NumberOfGuardians);

        // ── Step 1: Generate triple key pairs for each guardian ──────────────
        for (var i = 1; i <= options.NumberOfGuardians; i++)
        {
            Console.WriteLine($"  Generating keys for guardian {i}...");

            using var keySet = new GuardianKeySet((ulong)i, (ulong)options.Quorum);

            // Extract hex-encoded public keys while the native handle is alive
            var voteKeyHex = keySet.VotePublicKey.ToHex();
            var dataKeyHex = keySet.DataPublicKey.ToHex();
            var commKeyHex = keySet.CommunicationPublicKey.ToHex();

            voteKeyHexes.Add(voteKeyHex);
            dataKeyHexes.Add(dataKeyHex);

            var guardianSummary = new GuardianKeySummary
            {
                GuardianIndex = i,
                VotePublicKey = voteKeyHex,
                DataPublicKey = dataKeyHex,
                CommunicationPublicKey = commKeyHex,
            };
            guardianSummaries.Add(guardianSummary);

            // Write per-guardian key file
            var guardianFile = Path.Combine(options.OutDir, $"guardian_{i}_keys.json");
            File.WriteAllText(guardianFile,
                JsonConvert.SerializeObject(guardianSummary, Formatting.Indented));
            Console.WriteLine($"    Written: {guardianFile}");
        }

        // ── Step 2: Compute joint public keys ─────────────────────────────────
        Console.WriteLine("  Computing joint public keys...");
        var jointVoteKeyHex = ComputeJointKeyHex(voteKeyHexes);
        var jointDataKeyHex = ComputeJointKeyHex(dataKeyHexes);

        // ── Step 3: Write ceremony summary ────────────────────────────────────
        var ceremony = new KeyCeremonySummary
        {
            NumberOfGuardians = options.NumberOfGuardians,
            Quorum = options.Quorum,
            JointVotePublicKey = jointVoteKeyHex,
            JointDataPublicKey = jointDataKeyHex,
            Guardians = guardianSummaries,
        };

        var summaryFile = Path.Combine(options.OutDir, "key_ceremony_summary.json");
        File.WriteAllText(summaryFile,
            JsonConvert.SerializeObject(ceremony, Formatting.Indented));

        Console.WriteLine($"\nKey Ceremony Complete.");
        Console.WriteLine($"  Summary: {summaryFile}");
        Console.WriteLine($"  Joint Vote Key (K):     {TruncateHex(jointVoteKeyHex)}");
        Console.WriteLine($"  Joint Data Key (K_hat): {TruncateHex(jointDataKeyHex)}");
        Console.WriteLine(
            $"\nNext step: use 'create-election' with -k (vote key) and -K (data key) to build a v2.1 context.");

        return Task.CompletedTask;
    }

    /// <summary>
    /// Compute the modular product of all guardian keys.
    /// Uses <see cref="ElementModP.MultModP(ElementModP)"/> which reassigns the
    /// accumulator in place and does not touch the right-hand side handle.
    /// </summary>
    private static string ComputeJointKeyHex(IReadOnlyList<string> keyHexes)
    {
        if (keyHexes.Count == 0)
            throw new ArgumentException("No keys provided for joint key computation.");

        // Start accumulator with first guardian's key
        using var joint = new ElementModP(keyHexes[0]);

        // Multiply by each subsequent guardian key
        for (var i = 1; i < keyHexes.Count; i++)
        {
            // Create a temporary ElementModP for the rhs; MultModP does NOT
            // modify rhs, only reassigns `joint`'s handle to the new product.
            using var rhs = new ElementModP(keyHexes[i]);
            joint.MultModP(rhs);
        }

        return joint.ToHex();
    }

    private static string TruncateHex(string hex) =>
        hex.Length > 16 ? $"{hex[..16]}…" : hex;
}

/// <summary>Summary for a single guardian's key set (public keys only).</summary>
internal class GuardianKeySummary
{
    public int GuardianIndex { get; set; }

    /// <summary>Vote encryption public key K_i (hex).</summary>
    public string VotePublicKey { get; set; } = string.Empty;

    /// <summary>Ballot data encryption public key K_hat_i (hex).</summary>
    public string DataPublicKey { get; set; } = string.Empty;

    /// <summary>Guardian communication public key kappa_i (hex).</summary>
    public string CommunicationPublicKey { get; set; } = string.Empty;
}

/// <summary>Summary for a completed key ceremony, including joint public keys.</summary>
internal class KeyCeremonySummary
{
    public int NumberOfGuardians { get; set; }
    public int Quorum { get; set; }

    /// <summary>
    /// Joint vote encryption public key K = ∏ K_i (mod p).
    /// Pass as <c>--publicKey</c> to <c>create-election</c>.
    /// </summary>
    public string JointVotePublicKey { get; set; } = string.Empty;

    /// <summary>
    /// Joint ballot data public key K_hat = ∏ K_hat_i (mod p).
    /// Pass as <c>--ballot-data-key</c> to <c>create-election</c> for v2.1 contexts.
    /// </summary>
    public string JointDataPublicKey { get; set; } = string.Empty;

    /// <summary>Per-guardian key summaries (public portion only).</summary>
    public List<GuardianKeySummary> Guardians { get; set; } = new();
}
