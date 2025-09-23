namespace WinRm.NET.Internal.Kerberos
{
    using System;
    using global::Kerberos.NET;
    using global::Kerberos.NET.Crypto;

    internal class DecryptedWinRmKrbApRep : DecryptedKrbApRep
    {
        private const int TickUSec = 1000000;

        public DecryptedWinRmKrbApRep(global::Kerberos.NET.Entities.KrbApRep response)
            : base(response)
        {
        }

        public override void Validate(ValidationActions validation)
        {
            var now = this.Now();

            var ctime = this.Response.CTime.AddTicks(this.Response.CuSec / 10);

            if (validation.HasFlag(ValidationActions.TokenWindow))
            {
                this.ValidateTicketSkew(now, this.Skew, ctime);
            }

            if (!TimeEquals(this.CTime, this.Response.CTime))
            {
                throw new KerberosValidationException(
                    $"CTime does not match. Sent: {this.CTime.Ticks}; Received: {this.Response.CTime.Ticks}",
                    nameof(this.CTime));
            }

            if (this.CuSec != this.Response.CuSec)
            {
                throw new KerberosValidationException(
                    $"CuSec does not match. Sent: {this.CuSec}; Received: {this.Response.CuSec}",
                    nameof(this.CuSec));
            }
        }

        public static bool TimeEquals(DateTimeOffset left, DateTimeOffset right)
        {
            var leftUsec = left.Ticks / (TickUSec * 10);
            var rightUsec = right.Ticks / (TickUSec * 10);

            return leftUsec == rightUsec;
        }
    }
}
