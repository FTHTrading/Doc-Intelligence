// ─────────────────────────────────────────────────────────────
// Sovereign Comms Agent — Inbound Router
//
// HTTP webhook handler for Telnyx inbound messages.
// Handles:
//   • Incoming SMS / MMS
//   • Delivery receipts
//   • Opt-out (STOP) and opt-in (START) compliance
//   • HELP keyword handling
//   • Sender validation (block lists, opt-out checks)
//   • Number registry lookups
//   • Message parsing and normalization
//   • Routing to AI intent engine
//
// Telnyx webhook format reference:
//   POST /webhook/telnyx
//   Content-Type: application/json
//   {
//     "data": {
//       "event_type": "message.received",
//       "payload": {
//         "from": { "phone_number": "+1..." },
//         "to": [{ "phone_number": "+1..." }],
//         "text": "SIGN",
//         "id": "msg-uuid",
//         "received_at": "ISO8601",
//         "media": []
//       }
//     }
//   }
//
// ─────────────────────────────────────────────────────────────

import crypto from "crypto";
import http from "http";
import { getTelecomRegistry, TelecomNumber } from "./telecomRegistry";

// ── Types ────────────────────────────────────────────────────

/** Telnyx webhook event type */
export type TelnyxEventType =
  | "message.received"
  | "message.sent"
  | "message.finalized"
  | "message.delivery.failed";

/** Normalized inbound message */
export interface InboundMessage {
  /** Unique message ID */
  messageId: string;
  /** Telnyx message ID */
  telnyxMessageId: string;
  /** Sender phone (E.164) */
  from: string;
  /** Recipient phone (E.164) — your Telnyx number */
  to: string;
  /** Raw message text */
  rawText: string;
  /** Normalized text (uppercase, trimmed) */
  normalizedText: string;
  /** Extracted keyword (first word) */
  keyword: string;
  /** Remaining text after keyword */
  body: string;
  /** Media attachments (MMS) */
  media: MediaAttachment[];
  /** When received */
  receivedAt: string;
  /** When processed */
  processedAt: string;
  /** The registry entry for the destination number */
  targetNumber: TelecomNumber | null;
  /** Whether sender is a known contact */
  knownSender: boolean;
  /** Client IP (from webhook) */
  sourceIp: string;
}

/** Media attachment from MMS */
export interface MediaAttachment {
  /** Content type */
  contentType: string;
  /** URL to media */
  url: string;
  /** Size in bytes */
  size: number;
}

/** Delivery receipt */
export interface DeliveryReceipt {
  /** Telnyx message ID */
  telnyxMessageId: string;
  /** Status */
  status: "sent" | "delivered" | "failed";
  /** Error code (if failed) */
  errorCode?: string;
  /** Error message (if failed) */
  errorMessage?: string;
  /** Timestamp */
  timestamp: string;
}

/** Routing result from inbound handler */
export interface RoutingResult {
  /** Whether message was accepted */
  accepted: boolean;
  /** How it was handled */
  handledAs: "compliance" | "intent" | "blocked" | "error" | "receipt";
  /** Reason for handling decision */
  reason: string;
  /** The parsed inbound message (if accepted) */
  message?: InboundMessage;
  /** Auto-response sent (if any) */
  autoResponse?: string;
  /** Delivery receipt (if receipt event) */
  receipt?: DeliveryReceipt;
}

/** Compliance keyword */
type ComplianceKeyword = "STOP" | "STOPALL" | "UNSUBSCRIBE" | "CANCEL" | "END" | "QUIT"
  | "START" | "SUBSCRIBE" | "YES"
  | "HELP" | "INFO";

const STOP_KEYWORDS: Set<string> = new Set(["STOP", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END", "QUIT"]);
const START_KEYWORDS: Set<string> = new Set(["START", "SUBSCRIBE", "YES"]);
const HELP_KEYWORDS: Set<string> = new Set(["HELP", "INFO"]);

// ── Inbound Router ───────────────────────────────────────────

export class InboundRouter {
  private registry = getTelecomRegistry();

  /**
   * Process a raw Telnyx webhook payload.
   */
  processWebhook(
    rawBody: string,
    sourceIp: string
  ): RoutingResult {
    let parsed: any;
    try {
      parsed = JSON.parse(rawBody);
    } catch {
      return {
        accepted: false,
        handledAs: "error",
        reason: "Invalid JSON payload",
      };
    }

    const eventType: TelnyxEventType = parsed?.data?.event_type;

    // Handle delivery receipts
    if (eventType === "message.sent" || eventType === "message.finalized" || eventType === "message.delivery.failed") {
      return this.handleDeliveryReceipt(parsed);
    }

    // Only process inbound messages
    if (eventType !== "message.received") {
      return {
        accepted: false,
        handledAs: "error",
        reason: `Unhandled event type: ${eventType}`,
      };
    }

    return this.handleInbound(parsed, sourceIp);
  }

  /**
   * Handle an inbound message.
   */
  private handleInbound(parsed: any, sourceIp: string): RoutingResult {
    const payload = parsed?.data?.payload;
    if (!payload) {
      return {
        accepted: false,
        handledAs: "error",
        reason: "Missing payload in webhook data",
      };
    }

    // Parse message
    const from = payload.from?.phone_number || "";
    const to = payload.to?.[0]?.phone_number || payload.to?.phone_number || "";
    const rawText = payload.text || "";
    const normalizedText = rawText.trim().toUpperCase();
    const parts = normalizedText.split(/\s+/);
    const keyword = parts[0] || "";
    const body = parts.slice(1).join(" ");
    const telnyxMessageId = payload.id || "";
    const receivedAt = payload.received_at || new Date().toISOString();

    const media: MediaAttachment[] = (payload.media || []).map((m: any) => ({
      contentType: m.content_type || "application/octet-stream",
      url: m.url || "",
      size: m.size || 0,
    }));

    // Look up destination number in registry
    const targetNumber = this.registry.lookupNumber(to);

    // Record inbound on the number
    this.registry.recordInbound(to);

    // Build normalized message
    const message: InboundMessage = {
      messageId: crypto.randomBytes(16).toString("hex"),
      telnyxMessageId,
      from,
      to,
      rawText,
      normalizedText,
      keyword,
      body,
      media,
      receivedAt,
      processedAt: new Date().toISOString(),
      targetNumber,
      knownSender: false, // Will be enriched by intent engine
      sourceIp,
    };

    // ── Compliance checks (before anything else) ──

    // Check opt-out
    if (this.registry.isOptedOut(from)) {
      return {
        accepted: false,
        handledAs: "blocked",
        reason: "Sender has opted out",
        message,
      };
    }

    // Check block list
    if (targetNumber && this.registry.isBlocked(to, from)) {
      return {
        accepted: false,
        handledAs: "blocked",
        reason: "Sender is blocked on this number",
        message,
      };
    }

    // Handle STOP keywords
    if (STOP_KEYWORDS.has(keyword)) {
      this.registry.recordOptOut(from);
      const stopResponse = targetNumber?.compliance.stopResponse
        || "You have been unsubscribed. Reply START to re-subscribe.";
      return {
        accepted: true,
        handledAs: "compliance",
        reason: `STOP processed — sender opted out`,
        message,
        autoResponse: stopResponse,
      };
    }

    // Handle START keywords
    if (START_KEYWORDS.has(keyword)) {
      this.registry.recordOptIn(from);
      return {
        accepted: true,
        handledAs: "compliance",
        reason: "START processed — sender opted in",
        message,
        autoResponse: "You have been re-subscribed to FTH Trading messages.",
      };
    }

    // Handle HELP keywords
    if (HELP_KEYWORDS.has(keyword)) {
      const helpResponse = targetNumber?.compliance.helpResponse
        || "FTH Trading Support. Email support@fthtrading.com for assistance.";
      return {
        accepted: true,
        handledAs: "compliance",
        reason: "HELP response sent",
        message,
        autoResponse: helpResponse,
      };
    }

    // ── Route to intent engine ──
    return {
      accepted: true,
      handledAs: "intent",
      reason: "Routed to AI intent engine",
      message,
    };
  }

  /**
   * Handle delivery receipt events.
   */
  private handleDeliveryReceipt(parsed: any): RoutingResult {
    const payload = parsed?.data?.payload;
    const eventType = parsed?.data?.event_type;

    const receipt: DeliveryReceipt = {
      telnyxMessageId: payload?.id || "",
      status: eventType === "message.delivery.failed" ? "failed"
        : eventType === "message.finalized" ? "delivered"
        : "sent",
      errorCode: payload?.errors?.[0]?.code,
      errorMessage: payload?.errors?.[0]?.detail,
      timestamp: new Date().toISOString(),
    };

    return {
      accepted: true,
      handledAs: "receipt",
      reason: `Delivery receipt: ${receipt.status}`,
      receipt,
    };
  }

  /**
   * Route a direct message through compliance checks and return a RoutingResult.
   * Used for CLI simulation (--sca-simulate) without HTTP/webhook wrapping.
   */
  routeDirect(from: string, to: string, text: string): RoutingResult {
    const message = this.parseDirect(from, to, text);

    // Opt-out check
    if (this.registry.isOptedOut(from)) {
      return { accepted: false, handledAs: "blocked", reason: "Sender has opted out", message };
    }

    // Block list check
    if (message.targetNumber && this.registry.isBlocked(to, from)) {
      return { accepted: false, handledAs: "blocked", reason: "Sender is blocked on this number", message };
    }

    // STOP keywords
    if (STOP_KEYWORDS.has(message.keyword)) {
      this.registry.recordOptOut(from);
      const stopResponse = message.targetNumber?.compliance.stopResponse
        || "You have been unsubscribed. Reply START to re-subscribe.";
      return { accepted: true, handledAs: "compliance", reason: "STOP processed — sender opted out", message, autoResponse: stopResponse };
    }

    // START keywords
    if (START_KEYWORDS.has(message.keyword)) {
      this.registry.recordOptIn(from);
      return { accepted: true, handledAs: "compliance", reason: "START processed — sender opted in", message, autoResponse: "You have been re-subscribed to FTH Trading messages." };
    }

    // HELP keywords
    if (HELP_KEYWORDS.has(message.keyword)) {
      const helpResponse = message.targetNumber?.compliance.helpResponse
        || "FTH Trading Support. Email support@fthtrading.com for assistance.";
      return { accepted: true, handledAs: "compliance", reason: "HELP response sent", message, autoResponse: helpResponse };
    }

    // Route to intent
    return { accepted: true, handledAs: "intent", reason: "Routed to AI intent engine", message };
  }

  /**
   * Parse a raw text message into normalized format without webhook wrapping.
   * Used for direct/test message injection.
   */
  parseDirect(from: string, to: string, text: string): InboundMessage {
    const normalizedText = text.trim().toUpperCase();
    const parts = normalizedText.split(/\s+/);
    const keyword = parts[0] || "";
    const body = parts.slice(1).join(" ");
    const targetNumber = this.registry.lookupNumber(to);

    return {
      messageId: crypto.randomBytes(16).toString("hex"),
      telnyxMessageId: `direct-${Date.now()}`,
      from,
      to,
      rawText: text,
      normalizedText,
      keyword,
      body,
      media: [],
      receivedAt: new Date().toISOString(),
      processedAt: new Date().toISOString(),
      targetNumber,
      knownSender: false,
      sourceIp: "127.0.0.1",
    };
  }
}

// ── Telnyx Outbound API ──────────────────────────────────────

/**
 * Telnyx API configuration.
 * API key should be set via environment variable TELNYX_API_KEY.
 */
export interface TelnyxConfig {
  apiKey: string;
  apiUrl: string;
  messagingProfileId: string;
}

/**
 * Outbound message request.
 */
export interface OutboundMessage {
  from: string;
  to: string;
  text: string;
  mediaUrls?: string[];
  webhookUrl?: string;
}

/**
 * Outbound message result.
 */
export interface OutboundResult {
  success: boolean;
  messageId?: string;
  error?: string;
  rateLimited?: boolean;
}

/**
 * Send an outbound SMS via Telnyx V2 API.
 */
export async function sendTelnyxMessage(
  msg: OutboundMessage,
  config?: Partial<TelnyxConfig>
): Promise<OutboundResult> {
  const registry = getTelecomRegistry();

  // Rate limit check
  const rateCheck = registry.checkAndIncrementSend(msg.from);
  if (!rateCheck.allowed) {
    return {
      success: false,
      error: rateCheck.reason,
      rateLimited: true,
    };
  }

  // Opt-out check
  if (registry.isOptedOut(msg.to)) {
    return {
      success: false,
      error: "Recipient has opted out",
    };
  }

  const apiKey = config?.apiKey || process.env.TELNYX_API_KEY || "";
  const apiUrl = config?.apiUrl || "https://api.telnyx.com/v2/messages";

  if (!apiKey) {
    // If no API key, log as simulated
    console.log(`[SCA] SIMULATED SEND: ${msg.from} → ${msg.to}: ${msg.text.substring(0, 60)}...`);
    return {
      success: true,
      messageId: `sim-${crypto.randomBytes(8).toString("hex")}`,
    };
  }

  // Build request body
  const requestBody = JSON.stringify({
    from: msg.from,
    to: msg.to,
    text: msg.text,
    media_urls: msg.mediaUrls,
    messaging_profile_id: config?.messagingProfileId,
    webhook_url: msg.webhookUrl,
  });

  // Make HTTPS request
  return new Promise<OutboundResult>((resolve) => {
    const url = new URL(apiUrl);
    const options: http.RequestOptions = {
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`,
        "Content-Length": Buffer.byteLength(requestBody),
      },
    };

    // Use https module for actual API calls
    const protocol = url.protocol === "https:" ? require("https") : http;
    const req = protocol.request(options, (res: http.IncomingMessage) => {
      let data = "";
      res.on("data", (chunk: string) => { data += chunk; });
      res.on("end", () => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          try {
            const resp = JSON.parse(data);
            resolve({
              success: true,
              messageId: resp.data?.id || "unknown",
            });
          } catch {
            resolve({ success: true, messageId: "parse-error" });
          }
        } else {
          resolve({
            success: false,
            error: `Telnyx API error ${res.statusCode}: ${data.substring(0, 200)}`,
          });
        }
      });
    });

    req.on("error", (err: Error) => {
      resolve({
        success: false,
        error: `Network error: ${err.message}`,
      });
    });

    req.write(requestBody);
    req.end();
  });
}

// ── Singleton ────────────────────────────────────────────────

let _router: InboundRouter | null = null;

export function getInboundRouter(): InboundRouter {
  if (!_router) {
    _router = new InboundRouter();
  }
  return _router;
}
