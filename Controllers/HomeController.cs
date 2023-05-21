﻿using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using CompuTop.Core.Crypto;
using System.Text.RegularExpressions;
using System.Security.Cryptography.Xml;
using FormularPaygateAPI.Models;

namespace FormularPaygateAPI.Controllers
{
    public class HomeController : Controller
    {
        private const string PaygateUrl = "https://www.computop-paygate.com/passl.aspx";
        private const string MerchantID = "ct_devtraining";
        private const string EncryptionKey = "AaBbAaBbAaBbAaBb";

        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ProcessPayment(Amount model)
        {
            string transID = model.transID;
            string currency = model.currency;
            string urlSuccess = "https://youtu.be/WS4ifLGPaeQ"; 
            string urlFailure = "https://youtu.be/dQw4w9WgXcQ";
            string urlNotify = "https://youtu.be/CdqoNKCCt7A";

            // Build the parameter character string
            string parameterString = $"MerchantID={MerchantID}&TransID={model.transID}&Amount={model.amount}&Currency={model.currency}&URLSuccess={urlSuccess}&URLFailure={urlFailure}&URLNotify={urlNotify}";

            // Encrypt the parameter character string
            string encryptedParameterString = EncryptParameterStr(parameterString);

            // Build the Paygate interface URL
            string paygateUrl = $"https://www.computop-paygate.com/payssl.aspx?MerchantID={MerchantID}&Len={encryptedParameterString.Length}&Data={encryptedParameterString}";

            // Make the call to the Paygate interface
            string response = await SendHttpPostRequest(paygateUrl, "");

            // Return the Paygate response
            return Content(response, "text/html");
        }

        //Encrypt the parameter string using Blowfish ECB
        private string EncryptParameterStr(string parameterString)
        {
            HexCoding hexcoding = new HexCoding();
            BlowFish blowfish = new BlowFish(EncryptionKey, hexcoding);
            return blowfish.EncryptECB(parameterString);
        }
        private string[] DecryptResponse(string encryptedResponse)
        {
            // Implement decryption of the response using Blowfish ECB and the encryption key
            Regex LenInformation = new Regex(@"Len=(\d+)");
            Regex DataInformation = new Regex(@"Data=(\w+)");


            HexCoding hexcoding = new HexCoding();
            BlowFish blowfish = new BlowFish(EncryptionKey, hexcoding);

            // get Len from Response
            int iResponseLen = int.Parse(LenInformation.Match(encryptedResponse).Value);

            // get Data from Response
            string encryptData = DataInformation.Match(encryptedResponse).Value;

            // decrypt querystring from response + split into array
            string[] decryptedQueryPairs = blowfish.DecryptECB(encryptData, iResponseLen).Split('&');

            return decryptedQueryPairs;
        }

        private async Task<string> SendHttpPostRequest(string url, string postData)
        {
            using (var httpClient = new HttpClient())
            {
                var requestMessage = new HttpRequestMessage()
                {
                    Method = new HttpMethod("POST"),
                    RequestUri = new Uri(url),

                };
                requestMessage.Content = new StringContent(postData);
                requestMessage.Content!.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");
                requestMessage.Content.Headers.ContentLength = postData.Length;
                requestMessage.Content.Headers.Add("Charset", "UTF-8");


                var responses = await httpClient.SendAsync(requestMessage);

                var responseStatusCode = responses.StatusCode;
                var responseBody = await responses.Content.ReadAsStringAsync();
                if (responses.IsSuccessStatusCode)
                {
                    return responseBody;
                }
                else
                {
                    return string.Empty;
                }

            }
        }
    }
}
