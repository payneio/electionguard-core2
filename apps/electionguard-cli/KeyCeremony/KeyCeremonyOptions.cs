using CommandLine;

namespace ElectionGuard.CLI.KeyCeremony;

/// <summary>
/// CLI options for the v2.1 key ceremony command.
/// </summary>
[Verb("key-ceremony", HelpText = "Run a simulated v2.1 key ceremony, generating triple key pairs (vote/data/communication) for each guardian.")]
internal class KeyCeremonyOptions
{
    [Option('g', "guardians", Required = true, HelpText = "Number of guardians participating in the key ceremony.")]
    public int NumberOfGuardians { get; set; }

    [Option('q', "quorum", Required = true, HelpText = "Quorum of guardians required to decrypt (must be <= guardians).")]
    public int Quorum { get; set; }

    [Option('o', "out", Required = true, HelpText = "Output directory for key ceremony artifacts (per-guardian key files and summary).")]
    public string OutDir { get; set; } = string.Empty;

    public void Validate()
    {
        if (Quorum > NumberOfGuardians)
            throw new ArgumentException("Quorum cannot be greater than the number of guardians.");
        if (Quorum <= 0)
            throw new ArgumentException("Quorum must be greater than zero.");
        if (NumberOfGuardians <= 0)
            throw new ArgumentException("Number of guardians must be greater than zero.");

        if (!Directory.Exists(OutDir))
        {
            Console.WriteLine($"Creating output directory: {OutDir}");
            Directory.CreateDirectory(OutDir);
        }
    }
}
