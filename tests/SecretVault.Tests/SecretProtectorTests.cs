using System.Security.Cryptography;
using SecretVault.Web.Security;

namespace SecretVault.Tests;

public class SecretProtectorTests
{
    private static SecretProtector CreateProtector() =>
        new(RandomNumberGenerator.GetBytes(32));

    [Fact]
    public void Unprotect_ReturnsOriginalText()
    {
        var protector = CreateProtector();
        var original = "Пароль от Wi-Fi: Qwerty123!";

        var result = protector.Unprotect(protector.Protect(original));

        Assert.Equal(original, result);
    }

    [Fact]
    public void Protect_SameTextTwice_GivesDifferentResults()
    {
        // Шаг 1: создать protector
        var protector = CreateProtector();

        // Шаг 2: взять текст
        var text = "Логин и пароль пользователя: Skoob, genosha2042";

        // Шаг 3: зашифровать первый раз
        var first = protector.Protect(text);

        // Шаг 4: зашифровать тот же текст второй раз
        var second = protector.Protect(text);

        // Шаг 5: проверить, что результаты разные
        Assert.NotEqual(first, second);
    }
}
