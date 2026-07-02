import { Webhook } from "https://esm.sh/standardwebhooks@1.0.0";

type SendSmsEvent = {
  user?: { phone?: string };
  sms?: { otp?: string; phone?: string };
};

function getEnvOrThrow(key: string): string {
  const value = Deno.env.get(key);
  if (!value) {
    throw new Error(`Environment variable ${key} is not set`);
  }
  return value;
}

const ACCESS_KEY_ID = getEnvOrThrow("ALIYUN_ACCESS_KEY_ID");
const ACCESS_KEY_SECRET = getEnvOrThrow("ALIYUN_ACCESS_KEY_SECRET");
const SMS_SIGN_NAME = getEnvOrThrow("ALIYUN_SMS_SIGN_NAME");
const SMS_TEMPLATE_CODE = getEnvOrThrow("ALIYUN_SMS_TEMPLATE_CODE");
const HOOK_SECRET = getEnvOrThrow("SEND_SMS_HOOK_SECRET");
const ENDPOINT = "https://dysmsapi.aliyuncs.com/";

function getISOTime() {
  return new Date().toISOString().replace(/\.(\d{3})Z$/, "Z");
}

async function signAliyun(
  params: Record<string, string>,
  accessKeySecret: string,
) {
  const sorted = Object.keys(params)
    .sort()
    .map(
      (key) => `${encodeURIComponent(key)}=${encodeURIComponent(params[key])}`,
    )
    .join("&");
  const stringToSign = `POST&%2F&${encodeURIComponent(sorted)}`;
  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(`${accessKeySecret}&`),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    encoder.encode(stringToSign),
  );
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function sendAliyunSms(phone: string, code: string) {
  const params: Record<string, string> = {
    AccessKeyId: ACCESS_KEY_ID,
    Action: "SendSms",
    Format: "JSON",
    PhoneNumbers: phone,
    RegionId: "cn-hangzhou",
    SignName: SMS_SIGN_NAME,
    TemplateCode: SMS_TEMPLATE_CODE,
    TemplateParam: JSON.stringify({ code }),
    Timestamp: getISOTime(),
    SignatureMethod: "HMAC-SHA1",
    SignatureVersion: "1.0",
    SignatureNonce: crypto.randomUUID(),
    Version: "2017-05-25",
  };

  params.Signature = await signAliyun(params, ACCESS_KEY_SECRET);

  const response = await fetch(ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });
  const data = await response.json();
  if (data.Code !== "OK") {
    throw new Error(data.Message || "Aliyun SMS send failed");
  }
  return data;
}

const webhook = new Webhook(
  HOOK_SECRET.replace(/^v1,whsec_/, ""),
);

Deno.serve(async (req: Request) => {
  try {
    const payload = await req.text();
    const headers = Object.fromEntries(req.headers);

    if (req.method !== "POST") {
      return Response.json(
        { error: { http_code: 405, message: "Method Not Allowed" } },
        { status: 405 },
      );
    }

    let event: SendSmsEvent;
    try {
      event = webhook.verify(payload, headers) as SendSmsEvent;
    } catch (_) {
      return Response.json(
        { error: { http_code: 401, message: "Unauthorized: signature error" } },
        { status: 401 },
      );
    }

    const phone = event.sms?.phone ?? event.user?.phone;
    const code = event.sms?.otp;
    if (!phone || !code) {
      return Response.json(
        { error: { http_code: 400, message: "Missing phone or otp code" } },
        { status: 400 },
      );
    }

    await sendAliyunSms(phone, code);
    return Response.json(
      { message: "SMS sent successfully" },
      { status: 200 },
    );
  } catch (error) {
    console.error("[Error]:", error);
    return Response.json(
      { error: { http_code: 500, message: "Internal error" } },
      { status: 500 },
    );
  }
});
