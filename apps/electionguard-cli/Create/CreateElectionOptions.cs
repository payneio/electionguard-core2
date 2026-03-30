using CommandLine;

namespace ElectionGuard.CLI.Encrypt;

[Verb("create-election", HelpText = "Create an Election Package.")]
internal class CreateElectionOptions
{
    // ── v1.x options ──────────────────────────────────────────────────────────

    [Option('c', "commitment", Required = false, Default = "",
        HelpText = "The commitment hash that guardians make to each other (v1.x only; not needed for v2.1).")]
    public string CommitmentHash { get; set; } = string.Empty;

    // ── v2.1 option ───────────────────────────────────────────────────────────

    [Option('K', "ballot-data-key", Required = false, Default = "",
        HelpText = "Joint ballot data public key K_hat (v2.1). When supplied, the election context is " +
                   "built with CiphertextElectionContext.MakeV21() using the v2.1 hash chain " +
                   "(H_P, H_B, H_E). Omit for legacy v1.x contexts.")]
    public string BallotDataPublicKey { get; set; } = string.Empty;

    // ── Shared options ────────────────────────────────────────────────────────

    [Option('m', "manifest", Required = true, HelpText = "Json file containing an ElectionGuard manifest that contains election details.")]
    public string Manifest { get; set; } = string.Empty;

    [Option('g', "guardians", Required = true, HelpText = "The number of Guardians")]
    public int NumberOfGuardians { get; set; }

    [Option('q', "quorum", Required = true, HelpText = "The Quorum of guardians")]
    public int Quorum { get; set; }

    [Option('k', "publicKey", Required = true, Separator = ',', HelpText = "Joint ElGamal (vote) public key K from the key ceremony.")]
    public string ElGamalPublicKey { get; set; } = string.Empty;

    [Option('o', "out", Required = true, HelpText = "File folder in which to place encryption package.")]
    public string? OutDir { get; set; }

    /// <summary>Returns true when the caller supplied a ballot-data-key (K_hat), indicating v2.1 mode.</summary>
    public bool IsV21 => !string.IsNullOrWhiteSpace(BallotDataPublicKey);

    public void Validate()
    {
        if (Quorum > NumberOfGuardians)
        {
            throw new ArgumentException("Quorum cannot be greater than the number of guardians");
        }

        if (!IsV21 && string.IsNullOrWhiteSpace(CommitmentHash))
        {
            throw new ArgumentException(
                "Either --commitment (v1.x) or --ballot-data-key (v2.1) must be provided.");
        }

        ValidateDirectories();
        ValidateFiles();
    }

    private void ValidateDirectories()
    {
        if (string.IsNullOrEmpty(OutDir))
            throw new ArgumentNullException(nameof(OutDir));

        if (!Directory.Exists(OutDir))
        {
            Console.WriteLine($"Creating directory: {OutDir}");
            Directory.CreateDirectory(OutDir);
        }
    }

    private void ValidateFiles()
    {
        var requiredFiles = new[] { Manifest };
        var missingFiles = requiredFiles.Where(f => !File.Exists(f));
        foreach (var file in missingFiles)
        {
            throw new ArgumentException($"{file} does not exist");
        }
    }
}
