using NUnit.Framework;

namespace ElectionGuard.Encryption.Tests
{
    [TestFixture]
    public class TestV21Bindings
    {
        [Test]
        public void Test_V21_ContextMake_WithKHat()
        {
            // Generate two guardians for a 2-of-3 quorum
            var guardian1 = new GuardianKeySet(1, 2);
            var guardian2 = new GuardianKeySet(2, 2);
            var guardian3 = new GuardianKeySet(3, 2);

            Assert.IsNotNull(guardian1.VotePublicKey);
            Assert.IsNotNull(guardian1.DataPublicKey);
            Assert.IsNotNull(guardian1.CommunicationPublicKey);

            // Use simple manifest bytes for test
            byte[] manifest = System.Text.Encoding.UTF8.GetBytes("{}");

            // Create v2.1 election context
            // Note: In a real scenario, you'd compute joint keys from all guardians
            // For this test, just use guardian1's keys directly
            var context = CiphertextElectionContext.MakeV21(
                3, 2,
                guardian1.VotePublicKey,
                guardian1.DataPublicKey,
                manifest);

            Assert.IsNotNull(context);
            Assert.IsNotNull(context.CryptoBaseHash);
            Assert.IsNotNull(context.CryptoExtendedBaseHash);
            Assert.IsNotNull(context.BallotDataPublicKey);

            // Cleanup
            guardian1.Dispose();
            guardian2.Dispose();
            guardian3.Dispose();
            context.Dispose();
        }

        [Test]
        public void Test_V21_GuardianKeySet_Generate()
        {
            var guardian = new GuardianKeySet(1, 3);

            Assert.IsNotNull(guardian.VotePublicKey);
            Assert.IsNotNull(guardian.DataPublicKey);
            Assert.IsNotNull(guardian.CommunicationPublicKey);

            guardian.Dispose();
        }
    }
}
