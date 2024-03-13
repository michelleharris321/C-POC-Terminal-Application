// See https://aka.ms/new-console-template for more information
//string apiKey = "AIzaSyCrYen9QVd7kXasUXhFTcIpEKFyOHZUTCs";
//string projectId = "vivid-zodiac-415014";
//FIRST METHOD 

using System;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace WebRiskChecker
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // Google Cloud project ID
            string projectId = "vivid-zodiac-415014";
            // string projectId = Environment.GetEnvironmentVariable("PROJECT_ID");

            // API Key for Web Risk API
            string apiKey = "AIzaSyA1B_hwz-yeMsxz76ua_nROlJDk85GWJyo";
            // string apiKey = Environment.GetEnvironmentVariable("API_KEY");

            // URL to be checked
            Console.WriteLine("Enter URL to check:");
            string url = Console.ReadLine();

            // Check URL safety
            await CheckUrlSafety(projectId, apiKey, url);

            Console.ReadLine();
        }

        static async Task CheckUrlSafety(string projectId, string apiKey, string url)
        {
            try
            {
                using (HttpClient client = new HttpClient())
                {
                    client.DefaultRequestHeaders.Add("x-goog-api-key", apiKey);

                    string path = $"https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE&uri={url}&key={apiKey}";

                    HttpResponseMessage response = await client.GetAsync(path);

                    Console.WriteLine(response);

                    // Check response status
                    if (response.IsSuccessStatusCode)
                    {
                        // Read response content
                        string jsonResponse = await response.Content.ReadAsStringAsync();
                        Console.WriteLine(jsonResponse);

                        JsonNode result = JsonSerializer.Deserialize<JsonNode>(jsonResponse);

                        Console.WriteLine(result);

                        // Check if URL is flagged
                        if (result["threat"] != null && result["threat"]["threatTypes"] is JsonArray jsonArray)
                        {
                            foreach (var match in jsonArray)
                            {
                                Console.WriteLine($"URL is flagged as {match} by Google Web Risk API.");
                            }
                        }
                        else
                        {
                            Console.WriteLine("URL is safe according to Google Web Risk API.");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Error: {response.ReasonPhrase}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }
    }
}


//SECOND METHOD
/*using System;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace WebRiskChecker
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // Your Google Cloud project ID
            string projectId = "vivid-zodiac-415014";
            
            // API Key for Web Risk API
            string apiKey = "AIzaSyA1B_hwz-yeMsxz76ua_nROlJDk85GWJyo";

            // URL to be checked
            Console.WriteLine("Enter URL to check:");
            string url = Console.ReadLine();

            // Check URL safety
            await CheckUrlSafety(projectId, apiKey, url);

            Console.ReadLine();
        }

        static async Task CheckUrlSafety(string projectId, string apiKey, string url)
        {
            try
            {
                using (HttpClient client = new HttpClient())
                {
                    client.DefaultRequestHeaders.Add("x-goog-api-key", apiKey);

                    string path = $"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={apiKey}";

                    // Construct request body
                    var requestBody = new
                    {
                        client = new
                        {
                            clientId = projectId,
                            clientVersion = "1.5.2"
                        },
                        threatInfo = new
                        {
                            threatTypes = new[] { "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION" },
                            platformTypes = new[] { "ANY_PLATFORM" },
                            threatEntryTypes = new[] { "URL" },
                            threatEntries = new[] { new { url = url } }
                        }
                    };

                    // Serialize request body to JSON
                    var jsonRequestBody = JsonSerializer.Serialize(requestBody);

                    // Send POST request
                    HttpResponseMessage response = await client.PostAsync(path, new StringContent(jsonRequestBody));

                    Console.WriteLine(response);

                    // Check response status
                    if (response.IsSuccessStatusCode)
                    {
                        // Read response content
                        string jsonResponse = await response.Content.ReadAsStringAsync();
                        Console.WriteLine(jsonResponse);

                        JsonNode result = JsonSerializer.Deserialize<JsonNode>(jsonResponse);

                        Console.WriteLine(result);

                        // Check if URL is flagged
                        if (result["matches"] != null && result["matches"] is JsonArray jsonArray)
                        {
                            foreach (var match in jsonArray)
                            {
                                Console.WriteLine($"URL is flagged as {match["threatType"]} by Google Safe Browsing API.");
                            }
                        }
                        else
                        {
                            Console.WriteLine("URL is safe according to Google Safe Browsing API.");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Error: {response.ReasonPhrase}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }
    }
}
*/

