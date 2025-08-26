# OAB iPay Merchant Integration

## Introduction
This document outlines the steps required for a merchant to integrate with the OAB payment gateway. The integration will enable merchants to initiate payments, handle responses, and ensure secure transaction processing.

## Prerequisites
Before starting the integration, ensure the following:
- Key credentials:
  - Id (tranportalId)
  - Password
  - ResourceKey
- Secure communication over HTTPS

## Transaction Types
### Purchase Transaction
#### Request Processing:
```csharp
// Define key details
string tranportalId = "your_tranportal_id";
string password = "your_password";
string resourceKey = "your_resource_key";
string mode = "SANDBOX"; // SANDBOX , PRODUCTION
string currency = "512";
string language = "EN";
string receiptURL = "https://merchant.com/responseurl/";
string errorURL = "https://merchant.com/errorurl/";
string trackid = "87234234234";

// Create a new request instance
Request req = new Request();

// Set required fields
req.Id = tranportalId;
req.Password = password;
req.ResourceKey = resourceKey;
req.Mode = mode;
req.CurrencyCode = currency;
req.LangId = language;
req.ResponseURL = receiptURL;
req.ErrorURL = errorURL;
req.Amt = amount;
req.TrackId = trackid;

// Set user-defined fields
req.Udf1 = "User Defined value 1";
req.Udf2 = "User Defined value 2";
req.Udf3 = "User Defined value 3";
req.Udf4 = "User Defined value 4";
req.Udf5 = "User Defined value 5";

// For Token transactions (Optional)
req.TokenNo = tokenNo;
req.TokenFlag = tokenFlag;

// Enable split payment (Optional)
req.SplitPaymentIndicator = "1";

// Create and configure split payment payload (Optional)
SplitPaymentPayload splitPayLoad = new SplitPaymentPayload();
string splittrackid = "87234234234932334";
splitPayLoad.AliasName = "account001";
splitPayLoad.Notes = "Salary";
splitPayLoad.Type = "1";
splitPayLoad.Reference = splittrackid;
splitPayLoad.SplitAmount = "10";

// Add split payment details to the request (Optional)
req.AddSplitPaymentPayload(splitPayLoad);

// Prepare the request transaction data
RequestTranData reqTranData = OabIpayRequestBuilder.PrepareRequestTranData(req);
```

#### Form Submission:
```html
<form action="<%=reqTranData.WebAddress %>" method="post">
   <input type="hidden" name="tranportalId" value="<%= reqTranData.TranportalId%>" />
   <input type="hidden" name="responseURL" value="<%= reqTranData.ResponseURL%>" />
   <input type="hidden" name="errorURL" value="<%= reqTranData.ErrorURL%>" />
   <input type="hidden" name="trandata" value="<%= reqTranData.TranData%>" />
   <button type="submit">Submit</button>
</form>
```

### Response Processing
```csharp
// Define key details
string tranportalId = "your_tranportal_id";
string password = "your_password";
string resourceKey = "your_resource_key";

// Retrieve parameters from request
string replyTranData = request["trandata"];
string trackId = request["trackId"];

// Create a new ReplyTranData instance and set values
ReplyTranData tranData = new ReplyTranData();
tranData.Id = tranportalId;
tranData.Password = password;
tranData.ResourceKey = resourceKey;
tranData.TranData = replyTranData;
tranData.TrackId = trackId;

// Process the transaction response
Reply reply = OabIpayReplyBuilder.PrepareReply(tranData);

// Retrieve result details
var result = reply.Result;
var date = reply.Date;
var refId = reply.Ref;
var auth = reply.Auth;
var trackId = reply.TrackId;
var tranId = reply.TranId;
var amt = reply.Amt;
var udf1 = reply.Udf1;
var udf2 = reply.Udf2;
var udf3 = reply.Udf3;
var udf4 = reply.Udf4;
var udf5 = reply.Udf5;
var paymentId = reply.PaymentId;
var tokenNo = reply.TokenNo;
var tranDate = reply.TranDate;
var tranRequestDate = reply.TranRequestDate;
var tranResponseDate = reply.TranResponseDate;
```

### Inquiry Transaction
```csharp
Reply reply = new OabIpayConnection().ProcessInquiryByTranId(req);
var result = reply.Result;
```

### Reversal Transaction
```csharp
Reply reply = new OabIpayConnection().ProcessReversalByTranId(req);
var result = reply.Result;
```

### Refund Transaction
```csharp
Reply reply = new OabIpayConnection().ProcessRefundByTranId(req);
var result = reply.Result;
```

## Security Guidelines
- Use HTTPS for all API calls.
- Store API keys securely and never expose them in client-side code.

## Support
For any issues or questions, contact our support team at **pg-support@oman-arabbank.com**.

