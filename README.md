# OAB iPay Merchant Integration (C#)

## Overview
This guide explains how to integrate with **OAB iPay** to process:
- **Purchase**
- **Inquiry**
- **Reversal**
- **Refund**

It also covers:
- **UDF1..UDF20** in request/response (optional)
- Response fields: **TokenNumber**, **BrandType**, **MaskedCard**
- How to interpret **Result** codes
- TrackId usage (must be unique)

---

## Prerequisites
You will receive the following credentials from OAB:
- `tranportalId` (Id)
- `password`
- `resourceKey`

You must provide:
- `ResponseURL` (success callback)
- `ErrorURL` (failure callback)

> Always use HTTPS.

---

## TrackId Rules (Important)
- `TrackId` must be **unique for every transaction request** you send (Purchase / Inquiry / Reversal / Refund).
- Do not reuse the same TrackId across different transactions.
- Recommended: use a UUID or your own sequence (with timestamp) to avoid collisions.

Example:
- `TrackId = "PAY-20260108-000001"`
- `TrackId = "PAY-20260108-000002"`

---

## Request Fields (Minimum)
For most transactions, you will use:
- `Id`, `Password`, `ResourceKey`
- `Mode` (`SANDBOX` or `PRODUCTION`) — primarily for Purchase
- `TrackId` (**unique**)
- `Amt`, `CurrencyCode` (commonly required for Inquiry/Reversal/Refund as per gateway expectation)
- `ResponseURL`, `ErrorURL` (Purchase)

> Note: Some SDKs use `Trackid` (lowercase `i`) instead of `TrackId`. Use the exact property name available in your model.

---

## UDF Fields (UDF1..UDF20) — Optional
UDF fields are **merchant-defined metadata**. Common examples include:
- Customer **Email**
- **Student Number**
- **Mobile Number**
- Internal reference IDs, session IDs, etc.

> Recommendation: keep the meaning of each UDF consistent (example: `Udf1=email`, `Udf2=studentNo`, `Udf3=mobile`).

### Example (set individually as needed)
```csharp
// UDF fields are optional. Set only the fields you need.
req.Udf1 = "student1@college.edu";   // Email
req.Udf2 = "STU-2026-000123";        // Student Number
req.Udf3 = "+9689XXXXXXX";           // Mobile Number

// Up to Udf20 is supported when required:
// req.Udf4 = "...";
// ...
// req.Udf20 = "...";
```

---

# Token Payments (Using TokenNumber)

## When to use
After a successful **Purchase**, the gateway may return a token in:
- `reply.TokenNumber`

You can store this token securely and use it for future token-based purchases.

## How to send token in the next Purchase
- Set `TokenFlag = 2`
- Set `TokenNumber` to the value received in the earlier purchase (`reply.TokenNumber`)

> Field names can differ by SDK (`TokenNumber` vs `TokenNo`). Use the field name available in your Request model.

### Example
```csharp
// From a previous successful purchase response:
string storedTokenNumber = reply.TokenNumber; // store this securely

// In the next purchase request:
req.TokenFlag   = "2";
req.TokenNumber = storedTokenNumber; // or req.TokenNo = storedTokenNumber (based on your SDK)
```

---

# Purchase

## 1) Build Purchase Request
```csharp
Request req = new Request
{
    Id          = "your_tranportal_id",
    Password    = "your_password",
    ResourceKey = "your_resource_key",

    Mode         = "SANDBOX",   // SANDBOX / PRODUCTION
    CurrencyCode = "512",
    LangId       = "EN",

    ResponseURL = "https://merchant.com/responseurl/",
    ErrorURL    = "https://merchant.com/errorurl/",

    TrackId = "PAY-20260108-000001",   // must be unique
    Amt     = "10.00"
};

// Optional: UDF1..UDF20 (set only what you need)
req.Udf1 = "student1@college.edu";   // Email
req.Udf2 = "STU-2026-000123";        // Student Number
req.Udf3 = "+9689XXXXXXX";           // Mobile Number

// Prepare request transaction data
RequestTranData reqTranData = OabIpayRequestBuilder.PrepareRequestTranData(req);
```

## 2) Post Form to Gateway
```html
<form action="<%= reqTranData.WebAddress %>" method="post">
  <input type="hidden" name="tranportalId" value="<%= reqTranData.TranportalId %>" />
  <input type="hidden" name="responseURL"  value="<%= reqTranData.ResponseURL %>" />
  <input type="hidden" name="errorURL"     value="<%= reqTranData.ErrorURL %>" />
  <input type="hidden" name="trandata"     value="<%= reqTranData.TranData %>" />
  <button type="submit">Pay Now</button>
</form>
```

---

# Response Handling (Purchase / Refund / Reversal)

## Decrypt and Parse Reply
```csharp
ReplyTranData tranData = new ReplyTranData
{
    Id          = "your_tranportal_id",
    Password    = "your_password",
    ResourceKey = "your_resource_key",
    TranData    = request["trandata"],
    TrackId     = request["trackId"]
};

Reply reply = OabIpayReplyBuilder.PrepareReply(tranData);
```

## Fields to Read From the Response
Use `reply` to read the fields you need for reconciliation and customer display.

### Common fields (recommended)
- `reply.Result`
- `reply.PaymentId`
- `reply.TranId`
- `reply.Ref`
- `reply.Auth`
- `reply.TrackId`
- `reply.Amt`

### UDF fields (if sent)
- `reply.Udf1` ... `reply.Udf20`

### Token / card fields (if provided by gateway)
- `reply.TokenNumber`
- `reply.BrandType`
- `reply.MaskedCard`

---

# Result Codes (Success / Failure)

The primary status field is:
- `reply.Result`

### Common result values
- **Success (typical):** `CAPTURED`, `SUCCESS`, `APPROVED`
- **Failure (typical):** `NOT CAPTURED`, `NOT APPROVED`

### Transaction-specific guidance
- **Purchase**
  - `CAPTURED` = success
  - `NOT CAPTURED` = failure
- **Inquiry**
  - `SUCCESS` = success
- **Approval-style responses (if applicable)**
  - `APPROVED` = success
  - `NOT APPROVED` = failure

> Always treat any unexpected/unknown `Result` value as **non-success** and handle it safely.

---

# Inquiry

## Inquiry by TrackId
```csharp
Request request = new Request();
request.TransId      = "original transaction track id"; // reference to original purchase track id (if required by your SDK)
request.Trackid      = "PAY-20260108-000002";            // must be unique for this inquiry request
request.Amt          = "10";
request.CurrencyCode = "512";

Reply reply = new OabIpayConnection().ProcessInquiryByTrackId(request);
```

## Inquiry by TranId (Transaction Id)
```csharp
Request request = new Request();
request.TransId      = "original transaction transaction id";
request.Trackid      = "PAY-20260108-000003"; // must be unique for this inquiry request
request.Amt          = "10";
request.CurrencyCode = "512";

Reply reply = new OabIpayConnection().ProcessInquiryByTranId(request);
```

---

# Reversal (by TranId)
```csharp
Request request = new Request();
request.TransId      = "original transaction transaction id";
request.Trackid      = "PAY-20260108-000004"; // must be unique for this reversal request
request.Amt          = "10";
request.CurrencyCode = "512";

Reply reply = new OabIpayConnection().ProcessReversalByTranId(request);
```

---

# Refund (by TranId)
```csharp
Request request = new Request();
request.TransId      = "original transaction transaction id";
request.Trackid      = "PAY-20260108-000005"; // must be unique for this refund request
request.Amt          = "10";
request.CurrencyCode = "512";

Reply reply = new OabIpayConnection().ProcessRefundByTranId(request);
```

---

## Security Notes
- Use HTTPS for all callbacks and API communication
- Never expose `Password` / `ResourceKey` in frontend code
- Store TokenNumber securely (do not expose in client-side code)
- Avoid logging sensitive values; prefer masked/tokenized values

---

## Support
For integration support, contact: **pg-support@oman-arabbank.com**
