using System;

namespace ElectionGuard
{
    /// <summary>
    /// v2.1 Guardian key set with triple key pairs (vote, data, communication).
    /// </summary>
    public class GuardianKeySet : DisposableBase
    {
        internal NativeInterface.GuardianKeySet.GuardianKeySetHandle Handle;

        /// <summary>
        /// Generate a new guardian key set with the specified index and quorum.
        /// </summary>
        public GuardianKeySet(ulong guardianIndex, ulong quorum)
        {
            var status = NativeInterface.GuardianKeySet.Generate(guardianIndex, quorum, out Handle);
            status.ThrowIfError();
        }

        internal GuardianKeySet(NativeInterface.GuardianKeySet.GuardianKeySetHandle handle)
        {
            Handle = handle;
        }

        /// <summary>
        /// The vote encryption public key K_i.
        /// </summary>
        public ElementModP VotePublicKey
        {
            get
            {
                var status = NativeInterface.GuardianKeySet.GetVotePublicKey(Handle, out var value);
                status.ThrowIfError();
                return new ElementModP(value);
            }
        }

        /// <summary>
        /// The ballot data encryption public key K_hat_i.
        /// </summary>
        public ElementModP DataPublicKey
        {
            get
            {
                var status = NativeInterface.GuardianKeySet.GetDataPublicKey(Handle, out var value);
                status.ThrowIfError();
                return new ElementModP(value);
            }
        }

        /// <summary>
        /// The communication public key kappa_i.
        /// </summary>
        public ElementModP CommunicationPublicKey
        {
            get
            {
                var status = NativeInterface.GuardianKeySet.GetCommunicationPublicKey(Handle, out var value);
                status.ThrowIfError();
                return new ElementModP(value);
            }
        }

        protected override void DisposeUnmanaged()
        {
            base.DisposeUnmanaged();
            if (Handle != null && !Handle.IsInvalid)
            {
                Handle.Dispose();
                Handle = null;
            }
        }
    }
}
