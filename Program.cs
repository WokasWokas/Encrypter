using System;
using System.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Encrypter
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
                if (message is null)
                    continue;
                var encrypted = encrypter.Encrypt(message);
                Console.WriteLine(encrypted);
                var decoded = encrypter.Decode(encrypted);
                Console.WriteLine(decoded);
            }
        }
    }
    class Encrypter
    {
        Encoding unicode = Encoding.UTF8;
        private readonly short KeyLength;
        private long FirstPrime;
        private long SecondPrime;
        private long MultiplyPrime;
        private long Euler;
        private long PublicKey;
        private long PrivateKey;
        private long Exponent;
        public Encrypter(short KeyLength)
        {
            this.KeyLength = KeyLength;
            GenerateKeys();
            Console.WriteLine("---------Information---------");
            Console.WriteLine($"First Prime: {FirstPrime}");
            Console.WriteLine($"Second Prime: {SecondPrime}");
            Console.WriteLine($"Multiply Prime: {MultiplyPrime}");
            Console.WriteLine($"Euler: {Euler}");
            Console.WriteLine($"Exponent: {Exponent}");
            Console.WriteLine($"NOD(Exponent, Euler): {gcd(Exponent, Euler)}");
            Console.WriteLine($"Public Key: {PublicKey}");
            Console.WriteLine($"Private Key: {PrivateKey}");
            Console.WriteLine("-----------------------------");
        }
        public string Encrypt(string message)
        {
            List<string> Blocks = SplitMessage(message, KeyLength);
            List<long> EncryptedBlocks = new List<long>();
            try
            {
                foreach (string Block in Blocks)
                {
                    byte[] bytes = unicode.GetBytes(Block.ToCharArray());
                    var IntegerMessage = KeyLength switch
                    {
                        2 => BitConverter.ToInt16(bytes, 0),
                        4 => BitConverter.ToInt32(bytes, 0),
                        8 => BitConverter.ToInt64(bytes, 0),
                        _ => 0,
                    };
                    if (IntegerMessage == 0)
                        throw new EmptyMessage("Message is empty or not readeble!");
                    EncryptedBlocks.Add((Square(IntegerMessage) * IntegerMessage) % PublicKey);
                }
            } catch (EmptyMessage e){
                Console.WriteLine(e);
                System.Environment.Exit(1);
            }
            return String.Join(' ', EncryptedBlocks);
        }
        public string Decode(string message)
        {
            string[] Blocks = message.Split(' ');
            List<string> DecodedMessage = new List<string>();
            try
            {
                foreach (string Block in Blocks)
                {
                    var block = KeyLength switch
                    {
                        2 => Int32.Parse(Block),
                        4 => Int32.Parse(Block),
                        8 => Int64.Parse(Block),
                        _ => 0,
                    };
                    var IntegerMessage = (MultiSquare(block, PrivateKey) * block) % PublicKey;
                    byte[] bytes = BitConverter.GetBytes(IntegerMessage);
                    DecodedMessage.Add(unicode.GetString(bytes));
                }
            } catch (System.FormatException) {
                Console.WriteLine("EmptyMessage: String can't be empty!");
            }
            return String.Join(' ', DecodedMessage);
        }
        private long MultiSquare(long num, long sq)
        {
            long q = num;
            if (sq % 2 != 0)
                sq--;
            for (int i = 0; i < sq / 2; i++)
                num *= q;
            return num;
        }
        private List<string> SplitMessage(string message, int BlockSize)
        {
            var result = (from Match m in Regex.Matches(message, @".{1," + BlockSize + "}")
                          select m.Value).ToList();
            return result;
        }
        private void GenerateKeys()
        {
            try
            {
                FirstPrime = GetPrimeNumber();
                if (FirstPrime == 1)
                    throw new WrongKeyLength("Wrong key length, prime numbers can't be created! Normal keys length: 2, 4, 8.");
                SecondPrime = GetPrimeNumber();
                if (SecondPrime == 1)
                    throw new WrongKeyLength("Wrong key length, prime numbers can't be created! Normal keys length: 2, 4, 8.");
                MultiplyPrime = FirstPrime * SecondPrime;
                PublicKey = MultiplyPrime;
                Euler = (FirstPrime - 1) * (SecondPrime - 1);
                Exponent = 3;
                PrivateKey = (gcd(Exponent, Euler) * Euler + 1) / Exponent;
            } catch (WrongKeyLength e) {
                Console.WriteLine(e);
                System.Environment.Exit(1);
            }
        }
        private long Square(long num) { return num * num; }
        private long gcd(long val1, long val2)
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
        private long GetPrimeNumber()
        {
            while (true)
            {
                byte[] bytes = RandomNumberGenerator.GetBytes(KeyLength);
                var PrimeNumber = KeyLength switch
                {
                    2 => BitConverter.ToInt16(bytes, 0),
                    4 => BitConverter.ToInt32(bytes, 0),
                    8 => BitConverter.ToInt64(bytes, 0),
                    _ => 0,
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
        private bool IsPrime(long num)
        {
            if (num % 2 == 0 | num % 3 == 0)
                return false;
            for (long i = 5; i * i < num; i += 4)
                if (num % i == 0 | num % (i + 2) == 0)
                    return false;
            return true;
        }
    }
    class EmptyMessage : Exception
    {
        public EmptyMessage()
        {
        }
        public EmptyMessage(string message)
            : base(message)
        {
        }
        public EmptyMessage(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
    class WrongKeyLength : Exception
    {
        public WrongKeyLength()
        {
        }
        public WrongKeyLength(string message)
            : base (message)
        {
        }
        public WrongKeyLength(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}