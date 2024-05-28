export const LINEAR_WEBHOOK_SIGNATURE_HEADER = "linear-signature";
export const LINEAR_WEBHOOK_TS_FIELD = "webhookTimestamp";

/**
 * Provides helper functions to work with Linear webhooks
 */
export class LinearWebhooks {
  public constructor(private secret: string) {}

  /**
   * Verify the webhook signature
   * @param rawBody The webhook request raw body.
   * @param signature The signature to verify.
   * @param timestamp The `webhookTimestamp` field from the request parsed body.
   */
  public async verify(rawBody: Buffer, signature: string, timestamp?: number): Promise<boolean> {
    const encoder = new TextEncoder();

    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(this.secret),
      { name: "HMAC", hash: { name: "SHA-256" } },
      false,
      ["sign"]
    );

    const signatureBuffer = new Uint8Array(Buffer.from(signature, 'hex'));

    const verificationArrayBuffer = await crypto.subtle.sign(
      "HMAC",
      key,
      rawBody
    );

    const verificationBuffer = new Uint8Array(verificationArrayBuffer);

    if (verificationBuffer.length !== signatureBuffer.length) {
      throw new Error("Invalid webhook signature");
    }

    // Timing-safe comparison
    let isValid = true;
    for (let i = 0; i < verificationBuffer.length; i++) {
      if (verificationBuffer[i] !== signatureBuffer[i]) {
        isValid = false;
      }
    }

    if (!isValid) {
      throw new Error("Invalid webhook signature");
    }

    if (timestamp) {
      const timeDiff = Math.abs(new Date().getTime() - timestamp);
      // Throw error if more than one minute delta between provided ts and current time
      if (timeDiff > 1000 * 60) {
        throw new Error("Invalid webhook timestamp");
      }
    }

    return true;
  }
}