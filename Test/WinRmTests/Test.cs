namespace WinRmTests
{
    using System;

    internal static class Test
    {
        public static bool SpansAreEqual(ReadOnlySpan<byte> s1, ReadOnlySpan<byte> s2)
        {
            if (s1.Length != s2.Length)
            {
                return false;
            }

            for(int i = 0; i < s1.Length; i++)
            {
                if (s1[i] != s2[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
