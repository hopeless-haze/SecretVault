using System.Security.Cryptography;
using System.Text;

namespace SecretVault.Web.Security;

public sealed class SecretProtector
{
    private const byte FormatVersion = 1;
    private const int KeySize = 32;   // AES-256
    private const int NonceSize = 12; // 96 бит — стандарт для GCM
    private const int TagSize = 16;   // 128 бит — максимальный тег
    private const int HeaderSize = 1 + NonceSize + TagSize;

    private readonly byte[] _key;

    public SecretProtector(byte[] key)
    {
        if (key is null || key.Length != KeySize)
            throw new ArgumentException($"Ключ должен быть ровно {KeySize} байта.", nameof(key));

        _key = key.ToArray(); // копия: тот, кто передал массив, не сможет подменить ключ потом
    }

    public string Protect(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        var plainBytes = Encoding.UTF8.GetBytes(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);   // 12 нулей — одинаковые каждый раз // новый для КАЖДОГО вызова
        var cipherBytes = new byte[plainBytes.Length];          // GCM не меняет длину
        var tag = new byte[TagSize];

        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plainBytes, cipherBytes, tag);

        // Собираем: [версия][nonce][тег][шифротекст]
        var result = new byte[HeaderSize + cipherBytes.Length];
        result[0] = FormatVersion;
        nonce.CopyTo(result, 1);
        tag.CopyTo(result, 1 + NonceSize);
        cipherBytes.CopyTo(result, HeaderSize);

        return Convert.ToBase64String(result);
    }

    public string Unprotect(string protectedValue)
    {
        ArgumentNullException.ThrowIfNull(protectedValue);


        var bytes = Convert.FromBase64String(protectedValue);

        if (bytes.Length < HeaderSize || bytes[0] != FormatVersion)
        throw new CryptographicException("Неверный формат зашифрованных данных");

        var nonce = bytes.AsSpan(1, NonceSize);
        var tag = bytes.AsSpan(1 + NonceSize, TagSize);
        var cipherBytes = bytes.AsSpan(HeaderSize);

        var plainBytes = new byte[cipherBytes.Length];
        using var aes = new AesGcm(_key, TagSize);
        aes.Decrypt(nonce, cipherBytes, tag, plainBytes);

        return Encoding.UTF8.GetString(plainBytes);
    }
}
