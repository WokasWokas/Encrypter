using System;
using System;
using System.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace GetOneOfNumber
{
    class Program
    {
        static void Main(string[] args)
        {
            Encrypter encrypter = new Encrypter(2);
            while (true)
            {
                Console.Write("Message: ");
                var message = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(message))
                    continue;
                var encrypted = encrypter.Encrypt(message);
                var decoded = encrypter.Decode(encrypted);
            }
        }
    }
    class Encrypter
    {
        Encoding unicode = Encoding.UTF8;
        private readonly ushort KeyLength;
        private ulong FirstPrime;
        private ulong SecondPrime;
        private ulong Euler;
        private ulong GCD;
        private ulong PublicKey;
        private ulong PrivateKey;
        private ulong Exponent;
        public Encrypter(ushort KeyLength)
        {
            this.KeyLength = KeyLength;
            GenerateKeys();
            Console.WriteLine("---------Information---------");
            Console.WriteLine($"First Prime: {FirstPrime}");
            Console.WriteLine($"Second Prime: {SecondPrime}");
            Console.WriteLine($"Euler: {Euler}");
            Console.WriteLine($"Exponent: {Exponent}");
            System.Console.WriteLine($"GCD: {GCD}");
            Console.WriteLine($"Public Key: {PublicKey}");
            Console.WriteLine($"Private Key: {PrivateKey}");
            Console.WriteLine("-----------------------------");
        }
        public string Encrypt(string message)
        {
            Console.WriteLine(' ');
            Console.WriteLine("Encrypting...");
            List<string> Blocks = SplitMessage(message, 8);
            List<ulong> EncryptedBlocks = new List<ulong>();
            if (SplitMessage(Blocks[^1], 1).Count != 8)
                Blocks[^1] += "       ";
            foreach (string Block in Blocks)
            {
                Console.WriteLine(' ');
                Console.WriteLine($"Block {Blocks.IndexOf(Block)}: ");
                byte[] bytes = unicode.GetBytes(Block);
                ulong IntegerMessage = BitConverter.ToUInt64(bytes);
                ulong IntegerValue = PowMod(IntegerMessage, Exponent, PublicKey);
                EncryptedBlocks.Add(IntegerValue);
                Console.WriteLine($"Value: {Block}");
                Console.WriteLine($"Bytes: {BitConverter.ToString(bytes)}");
                Console.WriteLine($"IntegerMessage: {IntegerMessage}");
                Console.WriteLine($"EncryptedValue: {IntegerValue}");
            }
            return String.Join(' ', EncryptedBlocks);
        }
        public string Decode(string message)
        {
            Console.WriteLine(' ');
            Console.WriteLine("Decoding...");
            string[] Blocks = message.Split(' ');
            List<string> DecodedMessage = new List<string>();
            foreach (string Block in Blocks)
            {
                Console.WriteLine(' ');
                Console.WriteLine($"Block #: ");
                ulong IntegerValue = UInt64.Parse(Block);
                ulong IntegerMessage = PowMod(IntegerValue, PrivateKey, PublicKey);
                byte[] bytes = BitConverter.GetBytes(IntegerMessage);
                DecodedMessage.Add(unicode.GetString(bytes));
                Console.WriteLine($"Value: {unicode.GetString(bytes)}");
                Console.WriteLine($"Bytes: {BitConverter.ToString(bytes)}");
                Console.WriteLine($"IntegerMessage: {IntegerMessage}");
                Console.WriteLine($"IntegerValue: {IntegerValue}");
            }
            return String.Join(' ', DecodedMessage);
        }

        private ulong PowMod(ulong x, ulong y, ulong n)
        {
            ulong r = 1;
            while (y != 0)
            {
                if ((y & 0x01) == 1)
                    r = (r * x) % n;
                x = (x * x) % n;
                y >>= 1;
            }
            return r;
        }
        private List<string> SplitMessage(string message, int BlockSize)
        {
            var result = (from Match m in Regex.Matches(message, @".{1," + BlockSize + "}")
                          select m.Value).ToList();
            return result;
        }
        private void GenerateKeys()
        {
            FirstPrime = GetPrimeNumber();
            SecondPrime = GetPrimeNumber();
            PublicKey = FirstPrime * SecondPrime;
            Euler = (FirstPrime - 1) * (SecondPrime - 1);
            Exponent = GetPrimeNumber();
            GCD = gcd(Euler, Exponent);
            PrivateKey = (GCD * Euler + 1) / Exponent;
        }
        private ulong gcd(ulong val1, ulong val2)
        {
            while ((val1 != 0) && (val2 != 0))
            {
                if (val1 > val2)
                    val1 -= val2;
                else
                    val2 -= val1;
            }
            return Math.Max(val1, val2);
        }
        private ulong GetPrimeNumber()
        {
            try
            {
                while (true)
                {
                    byte[] bytes = RandomNumberGenerator.GetBytes(KeyLength);
                    var PrimeNumber = KeyLength switch
                    {
                        2 => BitConverter.ToUInt16(bytes),
                        4 => BitConverter.ToUInt32(bytes),
                        8 => BitConverter.ToUInt64(bytes),
                        _ => throw new WrongKeyLength("Wrong Key Length! Try: 2, 4, 8"),
                    };
                    if (PrimeNumber < 0)
                        continue;
                    if (PrimeNumber == 0)
                        return 1;
                    if (IsPrime(PrimeNumber))
                        return PrimeNumber;
                    else
                        continue;
                }
            }
            catch (WrongKeyLength e)
            {
                Console.WriteLine(e);
                System.Environment.Exit(1);
            }
            return 0;
        }
        private bool IsPrime(ulong num)
        {
            if (num == 2 | num == 3)
                return true;
            if (num % 2 == 0 | num % 3 == 0)
                return false;
            for (ulong i = 5; i * i < num; i += 4)
                if (num % i == 0 | num % (i + 2) == 0)
                    return false;
            return true;
        }
    }
    class WrongKeyLength : Exception
    {
        public WrongKeyLength() { }
        public WrongKeyLength(string message) : base(message) { }
        public WrongKeyLength(string message, Exception ivv) : base(message, ivv) { }
    }
}