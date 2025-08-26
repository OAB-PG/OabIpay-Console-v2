using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Nodes;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.IO.Compression;
using System.Xml.Linq;
using System.Linq.Expressions;

namespace OAB
{

    public static class JsonUtil
    {
        public static JsonObject ObjectToJson(object obj)
        {
            JsonObject jsonObject = new JsonObject();
            foreach (var property in obj.GetType().GetProperties())
            {
                object value = property.GetValue(obj);
                if (value is ICollection<object> collection)
                {
                    JsonArray jsonArray = new JsonArray();
                    foreach (var item in collection)
                    {
                        jsonArray.Add(ObjectToJson(item));
                    }
                    jsonObject[property.Name] = jsonArray;
                }
                else
                {
                    jsonObject[property.Name] = JsonValue.Create(value);
                }
            }
            return jsonObject;
        }
    }
     public class OabIpayReplyBuilder
    {
        public static Reply PrepareReply(ReplyTranData tranData)
        {
            return ToPrepareReply(tranData);
        }

        private static Reply ToPrepareReply(ReplyTranData tranData)
        {
            return SecretUtil.Decrypt(tranData.ResourceKey, tranData.TranData);
        }
    }

    public class OabIpayRequestBuilder
    {
        public static RequestTranData PrepareRequestTranData(Request request)
        {
            return ToRequestTranData(request);
        }

        private static RequestTranData ToRequestTranData(Request request)
        {
            RequestTranData tranData = new RequestTranData();
            request.Action = "1";
            string mode = request.Mode;
            string key = request.ResourceKey;
            request.Trackid = request.TrackId;
            request.Langid = request.LangId;
            request.Currencycode = request.CurrencyCode;

            request.Mode = null;
            request.ResourceKey = null;
            request.TrackId = null;
            request.LangId = null;
            request.CurrencyCode = null;

            tranData.TranData = request.GetData(key);
            request.Mode = mode;
            tranData.WebAddress = request.GetWebAddress() + "transactionRoute.htm?param=tranRoute";

            tranData.ResponseURL = request.ResponseURL;
            tranData.ErrorURL = request.ErrorURL;
            tranData.TranportalId = request.Id;
            return tranData;
        }
    }

    public class ReplyTranData
    {
        public string TranData { get; set; }
        public string ResourceKey { get; set; }
        public string TrackId { get; set; }
        public string PaymentId { get; set; }
        public string Error { get; set; }
        public string ErrorText { get; set; }
    }

    public class Request
    {
        public string Id { get; set; }
        public string Password { get; set; }
        public string ResourceKey { get; set; }
        public string Mode { get; set; }
        public string Action { get; set; }
        public string Amt { get; set; }
        public string TrackId { get; set; }
        public string Trackid { get; set; }
        public string TransId { get; set; }
        public string TokenNo { get; set; }
        public string TokenFlag { get; set; }
        public string Udf1 { get; set; }
        public string Udf2 { get; set; }
        public string Udf3 { get; set; }
        public string Udf4 { get; set; }
        public string Udf5 { get; set; }
        public string CurrencyCode { get; set; }
        public string Currencycode { get; set; }
        public string LangId { get; set; }
        public string Langid { get; set; }
        public string ResponseURL { get; set; }
        public string ErrorURL { get; set; }
        public string SplitPaymentIndicator { get; set; }
        public List<SplitPaymentPayload> SplitPaymentPayload { get; set; } = new List<SplitPaymentPayload>();

        public void AddSplitPaymentPayload(SplitPaymentPayload splitPayLoad)
        {
            SplitPaymentPayload.Add(splitPayLoad);
        }
        public string GetData(string key)
        {
            return SecretUtil.Encrypt(this, key);
        }

        public string GetWebAddress()
        {
            return Mode switch
            {
                "PRODUCTION" => "https://securepayments.oabipay.com/trxns/",
                "SANDBOX" => "https://certpayments.oabipay.com/trxns/",
                _ => throw new ArgumentException($"{Mode} is not allowed.")
            };
        }

    }

    public class RequestTranData
    {
        public string TranData { get; set; }
        public string WebAddress { get; set; }
        public string TranportalId { get; set; }
        public string ResponseURL { get; set; }
        public string ErrorURL { get; set; }
    }

    public class Reply
    {
        public string Result { get; set; }
        public string PaymentId { get; set; }
        public string TranId { get; set; }
        public string Date { get; set; }
        public string Udf1 { get; set; }
        public string Udf2 { get; set; }
        public string Udf3 { get; set; }
        public string Udf4 { get; set; }
        public string Udf5 { get; set; }
        public string TrackId { get; set; }
        public string Auth { get; set; }
        public string Amt { get; set; }
        public string Ref { get; set; }
        public string Currency { get; set; }
        public string Error { get; set; }
        public string ErrorText { get; set; }
        public string TokenNo { get; set; }
        public string TranDate { get; set; }
        public string TranRequestDate { get; set; }
        public string TranResponseDate { get; set; }
        public List<SplitPaymentPayload> SplitPaymentPayload { get; set; } = new List<SplitPaymentPayload>();
    }

    public class SplitPaymentPayload
    {
        public long SplitTranId { get; set; }
        public string Reference { get; set; }
        public string AliasName { get; set; }
        public string SplitAmount { get; set; }
        public string Notes { get; set; }
        public string Description { get; set; }
        public string Type { get; set; }
    }

    public static class SecretUtil
    {
        public static string Encrypt(Request request, string key)
        {
            try
            {
                var options = new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                    WriteIndented = true
                };
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                if (keyBytes.Length == 16)
                {
                    keyBytes = keyBytes.Concat(keyBytes.Take(8)).ToArray();
                }
                if (keyBytes.Length != 24)
                {
                    throw new ArgumentException("Invalid key size for 3DES. Key must be 16 or 24 bytes.");
                }
                using (var tripleDes = TripleDES.Create())
                {
                    tripleDes.Key = keyBytes;
                    tripleDes.Mode = CipherMode.ECB;
                    tripleDes.Padding = PaddingMode.PKCS7;

                    byte[] plaintextBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request, options));
                    using (var encryptor = tripleDes.CreateEncryptor())
                    {
                        byte[] cipherText = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);
                        return BitConverter.ToString(cipherText).Replace("-", "");
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Error during encryption", ex);
            }
        }

        public static Reply Decrypt(string key, string value)
        {
            string decryptedStr = DecryptTranData(key, value);
            string cleanJson = decryptedStr.TrimEnd('^');
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };

            Reply reply = JsonSerializer.Deserialize<Reply>(cleanJson, options);
            return reply;
        }

        private static string DecryptTranData(string rkey, string value) {
            byte[] key = Encoding.ASCII.GetBytes(rkey);
            int NumberChars = value.Length / 2;
            byte[] data = new byte[NumberChars];
            StringReader sr = new StringReader(value);
            for (int i = 0; i < NumberChars; i++)
                data[i] = Convert.ToByte(new string(new char[2] { (char)sr.Read(), (char)sr.Read() }), 16);
            sr.Dispose();
            byte[] enc = new byte[0];
            TripleDES tdes = TripleDES.Create();
            tdes.Key = key;
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.Zeros;
            ICryptoTransform ict = tdes.CreateDecryptor();
            enc = ict.TransformFinalBlock(data, 0, data.Length);
            String decryptedStr = Encoding.ASCII.GetString(enc);
            return decryptedStr;
        }
        private static string GetTripleDesValue(string pin, string key1, string key2, string key3)
        {
            string decryptedKey = GetDexValue(pin, key1);
            decryptedKey = BinaryToHex(AsciiCharToBinary(decryptedKey)).ToUpper();
            decryptedKey = GetHexValue(decryptedKey, key2);
            decryptedKey = GetDexValue(decryptedKey, key3);
            return BinaryToHex(AsciiCharToBinary(decryptedKey)).ToUpper();
        }

        private static string GetDexValue(string pin, string key)
        {
            using (var tripleDes = TripleDES.Create())
            {
                tripleDes.Key = Encoding.UTF8.GetBytes(key);
                tripleDes.Mode = CipherMode.ECB;
                tripleDes.Padding = PaddingMode.None;
                using (var decryptor = tripleDes.CreateDecryptor())
                {
                    byte[] cipherText = StringToHexBytes(pin);
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }

        private static string GetHexValue(string pin, string key)
        {
            using (var tripleDes = TripleDES.Create())
            {
                tripleDes.Key = Encoding.UTF8.GetBytes(key);
                tripleDes.Mode = CipherMode.ECB;
                tripleDes.Padding = PaddingMode.None;
                using (var encryptor = tripleDes.CreateEncryptor())
                {
                    byte[] cipherText = StringToHexBytes(pin);
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                    return BitConverter.ToString(encryptedBytes).Replace("-", "");
                }
            }
        }

        private static string BinaryToHex(string binaryString)
        {
            if (binaryString == null) return null;
            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < binaryString.Length; i += 8)
            {
                string temp = binaryString.Substring(i, 8);
                int intValue = Convert.ToInt32(temp, 2);
                hexString.Append(intValue.ToString("X2"));
            }
            return hexString.ToString();
        }

        private static string AsciiCharToBinary(string asciiString)
        {
            if (asciiString == null) return null;
            return string.Concat(asciiString.Select(c => Convert.ToString(c, 2).PadLeft(8, '0')));
        }

        private static byte[] StringToHexBytes(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        private static string HexToString(string hex)
        {
            byte[] bytes = StringToHexBytes(hex);
            return Encoding.UTF8.GetString(bytes);
        }
    }

    public class OabIpayConnection : OabIpayConnectionImpl
    {
        public Reply ProcessInquiryByTrackId(Request req) => ProcessInquiry(req, "TrackID");
        public Reply ProcessInquiryByPaymentId(Request req) => ProcessInquiry(req, "PaymentID");
        public Reply ProcessInquiryByTranId(Request req) => ProcessInquiry(req, "");
        public Reply ProcessInquiryByRefNo(Request req) => ProcessInquiry(req, "SeqNum");
        public Reply ProcessRefundByTranId(Request req) => ProcessRefund(req);
        public Reply ProcessReversalByTrackId(Request req) => ProcessReversal(req, "TrackID");
        public Reply ProcessReversalByTranId(Request req) => ProcessReversal(req, "");
    }

    public class OabIpayConnectionImpl
    {
        protected Reply ProcessInquiry(Request request, string udf5)
        {
            string webAddress = request.GetWebAddress();
            request.Action = "8";
            request.Udf5 = udf5;
            request.ErrorURL = webAddress;
            request.ResponseURL = webAddress;
            string url = webAddress + "transactionRoute.htm?param=tranTCPIPRoute";
            return new Connection().ConnectIpay(url, request);
        }

        protected Reply ProcessRefund(Request request)
        {
            string webAddress = request.GetWebAddress();
            request.Action = "2";
            request.Udf5 = "";
            request.ErrorURL = webAddress;
            request.ResponseURL = webAddress;
            string url = webAddress + "transactionRoute.htm?param=tranTCPIPRoute";
            return new Connection().ConnectIpay(url, request);
        }

        protected Reply ProcessReversal(Request request, string udf5)
        {
            string webAddress = request.GetWebAddress();
            request.Action = "3";
            request.Udf5 = udf5;
            request.ErrorURL = webAddress;
            request.ResponseURL = webAddress;
            string url = webAddress + "transactionRoute.htm?param=tranTCPIPRoute";
            return new Connection().ConnectIpay(url, request);
        }
    }

    public class Connection
    {
        public Reply ConnectIpay(string webUrl, Request request)
        {
            using (var client = new HttpClient())
            {
                var options = new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                    WriteIndented = true
                };
                var content = new StringContent(JsonSerializer.Serialize(request, options), Encoding.UTF8, "application/json");
                var response = client.PostAsync(webUrl, content).Result;
                response.EnsureSuccessStatusCode();
                string responseData = response.Content.ReadAsStringAsync().Result;
                return ParseReply(responseData);
            }
        }

        public static Reply ParseReply(string response)
        {
            var json = JsonSerializer.Deserialize<JsonElement>(response);
            var reply = new Reply
            {
                Result = json.GetProperty("result").GetString(),
                PaymentId = json.GetProperty("paymentid").GetString(),
                TranId = json.GetProperty("tranid").GetString(),
                Ref = json.GetProperty("ref").GetString(),
                Amt = json.GetProperty("amt").GetString(),
                Auth = json.GetProperty("auth").GetString(),

                Udf1 = json.GetProperty("udf1").GetString(),
                Udf2 = json.GetProperty("udf2").GetString(),
                Udf3 = json.GetProperty("udf3").GetString(),
                Udf4 = json.GetProperty("udf4").GetString(),
                Udf5 = json.GetProperty("udf5").GetString(),

                TranResponseDate = json.GetProperty("tranResponseDate").GetString(),
                TranRequestDate = json.GetProperty("tranRequestDate").GetString(),
                TranDate = json.GetProperty("tranDate").GetString(),

                TrackId = json.TryGetProperty("trackid", out var track) ? track.GetString() : null,
                TokenNo = null, // not available in this JSON
                Error = json.TryGetProperty("Error", out var err) ? err.GetString() : null,
                ErrorText = json.TryGetProperty("ErrorText", out var errTxt) ? errTxt.GetString() : null,
                Currency = json.TryGetProperty("currency", out var curr) ? curr.GetString() : null,
                Date = null, // 'date' field not available
            };

            return reply;
        }
    }
}
