static void Main(string[] args)
{
    byte[] buf = new byte[] {};
    byte[] encoded = new byte[buf.Length];
    for (int i = 0; i < buf.Length; i++)
    {
        encoded[i] = (byte)((((uint)buf[i] ^ 2) + 7 & 0xFF));
    }

    uint c = 0;
    StringBuilder hex = new StringBuilder(encoded.Length * 2);
    foreach (byte b in encoded)
    {
        hex.AppendFormat("{0:D}, ", b);
        c++;
        if (c % 50 == 0) { hex.AppendFormat("_{0}", Environment.NewLine); }
    }
    Console.WriteLine("Final payload: " + hex.ToString());
}
