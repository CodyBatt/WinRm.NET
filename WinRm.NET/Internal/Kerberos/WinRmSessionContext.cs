namespace WinRm.NET.Internal.Kerberos
{
    using System;
    using global::Kerberos.NET;
    using global::Kerberos.NET.Client;
    using global::Kerberos.NET.Crypto;
    using global::Kerberos.NET.Entities;

    internal class WinRmSessionContext(ApplicationSessionContext applicationSessionContext)
    {
        public KrbApReq ApReq => applicationSessionContext.ApReq;

        public KrbEncryptionKey SessionKey => applicationSessionContext.SessionKey;

        public KrbEncryptionKey ServiceTicketSessionKey => applicationSessionContext.ServiceTicketSessionKey;

        public KrbEncryptionKey ClientSubSessionKey => applicationSessionContext.ClientSubSessionKey;

        public int? SequenceNumber { get; set; } = applicationSessionContext.SequenceNumber;

        public int CuSec => applicationSessionContext.CuSec;

        public DateTimeOffset CTime => applicationSessionContext.CTime;

        public KrbEncryptionKey AuthenticateServiceResponse(string apRepEncoded)
        {
            return AuthenticateServiceResponse(Convert.FromBase64String(apRepEncoded));
        }

        public KrbEncryptionKey AuthenticateServiceResponse(ReadOnlyMemory<byte> apRepBytes)
        {
            var apRep = KrbApRep.DecodeApplication(apRepBytes);

            var decrypted = new DecryptedWinRmKrbApRep(apRep)
            {
                CTime = this.CTime,
                CuSec = this.CuSec,
                SequenceNumber = this.SequenceNumber,
            };

            decrypted.Decrypt(this.ServiceTicketSessionKey.AsKey());
            decrypted.Validate(ValidationActions.TokenWindow);
            return decrypted.Response.SubSessionKey ?? this.SessionKey;
        }

        private void DecryptApRep(DecryptedKrbApRep decrypted)
        {
            foreach (var key in new[]
            {
                this.SessionKey,
                this.ServiceTicketSessionKey,
                this.ClientSubSessionKey,
            })
            {
                if (key == null)
                {
                    continue;
                }

                try
                {
                    decrypted.Decrypt(key.AsKey());
                    return;
                }
                catch (Exception)
                {
                    // Not this key, continue to the next one
                }
            }

            throw new InvalidOperationException("Failed to decrypt AP_REP with any of the provided keys.");
        }
    }
}
