using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

const string secretKey = "{{SECRET}}"; // secret key

string token = BuildJwt();

ParseJWT(token);

static string Base64UrlEncode(string input)
{
    var inputBytes = Encoding.UTF8.GetBytes(input);
    var base64 = Convert.ToBase64String(inputBytes);
    var base64Url = base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');

    return base64Url;
}

static string ComputeSignature(string input)
{
    var keyBytes = Encoding.UTF8.GetBytes(secretKey);
    using var algorithm = new HMACSHA256(keyBytes);
    var inputBytes = Encoding.UTF8.GetBytes(input);
    var signatureBytes = algorithm.ComputeHash(inputBytes);

    //return Base64UrlEncode(Encoding.UTF8.GetString(signatureBytes));
    return Convert.ToBase64String(signatureBytes);
}

static string Base64UrlDecode(string input)
{
    string base64 = input.Replace('-', '+').Replace('_', '/');
    while (base64.Length % 4 != 0)
    {
        base64 += '=';
    }
    var base64Bytes = Convert.FromBase64String(base64);

    return Encoding.UTF8.GetString(base64Bytes);

}

static string BuildJwt()
{
    var headers = new Header
    {
        alg = "HS256",
        typ = "JWT" 
    };

    DateTime currentTime = DateTime.UtcNow;
    DateTime futureTime = DateTime.UtcNow.AddHours(24);
    var payload = new Payload
    {
        exp     = ((DateTimeOffset)futureTime).ToUnixTimeSeconds(),
        iss     = "{{KEY}}",
        name    = "name of user",
        nbf     = ((DateTimeOffset)currentTime).ToUnixTimeSeconds(),
        sub     = "id of user",
        video   = new Video { room = "room name", roomJoin = true }
    };

    string encodedHeader = Base64UrlEncode(JsonSerializer.Serialize(headers));
    string encodedPayload = Base64UrlEncode(JsonSerializer.Serialize(payload));
    string unsignedToken = $"{encodedHeader}.{encodedPayload}";
    string signature = ComputeSignature(unsignedToken);
    string jwt = $"{unsignedToken}.{signature}";
    Console.WriteLine(jwt);
    Console.WriteLine();

    return jwt;
}

static void ParseJWT(string jwt)
{
    string[] jwtParts = jwt.Split('.');
    string header = Base64UrlDecode(jwtParts[0]);
    string payload = Base64UrlDecode(jwtParts[1]);
    string signature = jwtParts[2];
    string expectedSignature = ComputeSignature($"{jwtParts[0]}.{jwtParts[1]}");

    if (expectedSignature == signature)
    {
        Console.WriteLine("JWT signature is valid.");
    }
    else
    {
        Console.WriteLine("JWT signature is invalid.");
    }
    Console.ReadLine();
}

public class Header
{
    public string? alg { get; set; }
    public string? typ { get; set; }
}

public class Payload
{
    public long exp { get; set; } // Data e hora formato unix para expiração do token 
    public string? iss { get; set; } // O domínio da aplicação geradora do token
    public string? name { get; set; } // Nome do usuário que vai entrar na sala
    public long nbf { get; set; } // Define uma data e hora formato unix para qual o token não pode ser aceito antes dela
    public string? sub { get; set; } // ID do usuário que vai entrar na sala
    public Video? video { get; set; }
}

public class Video
{
    public string? room { get; set; } // Nome da sala que o usuário vai entrar
    public Boolean roomJoin { get; set; } // Verdadeiro para ele entrar na sala
}